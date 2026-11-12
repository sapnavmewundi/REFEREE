# REFEREE - Your Anti-Cheat Is the Rootkit

> "Ten million gamers installed my rootkit. The publisher signed it."

**Systematic reachability analysis of kernel driver attack surface on Windows.**
A research toolkit that answers the question defenders actually need answered:
*"Which kernel drivers on my fleet can a normal, unprivileged user process
open a handle to -- and what god-mode primitives does that hand them?"*

## The research contribution

Everyone knows anti-cheat drivers run at ring-0. Existing work (loldrivers.io,
BYOVD research) catalogs *known-vulnerable* drivers. REFEREE goes further with
**three-axis scoring** -- a systematic methodology nobody has published:

1. **Capability** (what the driver *can* do) -- PE import analysis for memory
   access, cross-process manipulation, and callback removal APIs
2. **Reachability** (who can *reach* it) -- device object ACL audit showing
   which drivers are accessible from medium-integrity/user-level processes
3. **Known vulnerability** (is it a *known* weak point) -- loldrivers.io
   cross-reference with SHA256 hash verification

The combination is the finding: a driver that scores high on all three axes
is **actually dangerous**, not just theoretically interesting. This cuts
through the noise that pure import scanning produces.

**Reachability depth (v2):** reachability is no longer a boolean. REFEREE now
records *which integrity tier* can open the device object — LOW (reachable
even from a sandboxed/AppContainer process) vs MEDIUM (standard-user token).
A LOW-tier driver is a far bigger finding and scores higher.

**Multi-source device enumeration + handle probe (v4):** the v2 scanner
checked *only* the service registry Security descriptor — which most drivers
don't have, leaving ~95% as "Unknown." v4 discovers device paths from five
sources (IoCreateDevice conventions, registry DeviceMap, device interface
classes, known driver-to-device mappings, and service Parameters keys), then
**ground-truths** each with a zero-access `CreateFileW` handle probe. The
probe is read-only (FILE_READ_ATTRIBUTES / zero-access), never sends IOCTLs,
and gives a definitive answer: the device object either opened (user-reachable)
or returned ACCESS_DENIED (restricted). This moves reachability coverage from
~5% to a majority of the driver fleet.

## What's new in v2

| # | Capability | Script |
|---|------------|--------|
| 1 | Multi-host fleet scan + aggregation | `auditor/Referee-Fleet.ps1` |
| 2 | Before/after install attack-surface delta | `auditor/Referee-Delta.ps1` |
| 3 | Reachability depth (LOW/MEDIUM tier) + exposure score | `auditor/Referee-DeepScan.ps1` |
| 4 | Gap analysis — what catalogs miss | `auditor/Referee-Gap.ps1` |
| 5 | Longitudinal / cross-host driver diffing | `auditor/Referee-DriverDiff.ps1` |
| 6 | Real-time driver-load monitor (Sysmon/EventLog) | `auditor/Referee-Monitor.ps1` |
| 7 | WDAC generate + audit-mode validation loop | `auditor/Referee-WDACValidate.ps1` |
| 8 | Interactive filterable dashboard | `auditor/dashboard.html` |
| 9 | Reproducible research aggregator + dataset schema | `research/analyze.py` |
| 10 | Fleet deployment harness (PSRemoting) | `auditor/Referee-Fleet.ps1` |

## Tools

### Deep Scanner (`auditor/Referee-DeepScan.ps1`) -- the headline tool
Full three-axis analysis of every loaded kernel driver. Produces:
- Risk-ranked leaderboard with per-axis scores
- **Reachability map** (USER_REACHABLE vs RESTRICTED vs Unknown) via
  multi-source device enumeration + `CreateFileW` handle probe
- Driver **category breakdown** (anti-cheat vs GPU vs OEM vs Microsoft)
- Auto-generated **WDAC block policy** (audit mode) for dangerous drivers
- JSON + Markdown reports with reachability method attribution

```powershell
# Requires Administrator for ACL reads
powershell -ExecutionPolicy Bypass -File auditor\Referee-DeepScan.ps1
```

### Signature Auditor (`auditor/Referee-Audit.ps1`)
Quick check: scans for 9 known anti-cheat driver families by signature.

### Capability Scanner (`auditor/Referee-CapScan.ps1`)
PE import analysis across all drivers. Precursor to the deep scan.

### LOLDrivers Cross-Reference (`auditor/Referee-LOLCheck.ps1`)
Downloads and cross-references the loldrivers.io database (702 entries)
with SHA256 hash verification to distinguish exact-match vulnerable
binaries from patched versions with the same filename.

### Dashboard Generator (`auditor/Generate-Report.ps1`)
Generates a self-contained dark-themed HTML dashboard from scan results.

### Interactive Dashboard (`auditor/dashboard.html`)
Drop a `deepscan-*.json` report in and explore it: stat cards, risk bar,
category heatmap, live filters (user-reachable, LOW-tier, LOLDrivers match,
CRITICAL/HIGH), search, and sortable columns. Runs entirely in-browser —
nothing is uploaded.

### Fleet Runner (`auditor/Referee-Fleet.ps1`)
Runs the DeepScan across N hosts over PSRemoting, pulls each JSON back, and
aggregates. Surfaces **config-drift drivers**: reachable on some hosts but
restricted on others.

### Attack-Surface Delta (`auditor/Referee-Delta.ps1`)
Diffs a "before" and "after" DeepScan. Headline use: snapshot → install a game
→ snapshot → quantify which user-reachable kernel drivers the install *added*.

### Gap Analysis (`auditor/Referee-Gap.ps1`)
The capability × catalog matrix. Finds reachable, high-capability drivers that
are **absent from loldrivers.io** — the attack surface a catalog-only triage
misses.

### Driver Diff (`auditor/Referee-DriverDiff.ps1`)
Same filename across hosts/time: flags signer changes, risk-posture drift, and
cosmetic "updates" (version string changed, capability fingerprint identical).

### Real-Time Monitor (`auditor/Referee-Monitor.ps1`)
Watches Sysmon ID 6 (or System 7045 fallback) for new driver loads and scores
each on the capability axis as it happens. Continuous control, not a snapshot.

### WDAC Validate (`auditor/Referee-WDACValidate.ps1`)
Builds a hash-based block policy from a report and **proves** it: static
coverage check (every intended driver covered, no excluded driver leaked),
optional compile + **audit-only** staging (blocks nothing), and `-Remove` revert.

### Research Aggregator (`research/analyze.py`)
Regenerates every figure and table deterministically from the JSON reports:
reachability funnel, category-risk chart, gap matrix, full axis breakdown,
summary. See `research/README.md` for the dataset schema.

### Detection Pack (`detections/`)
- **4 Sigma rules**: driver abuse pattern detection (out-of-path registration,
  non-game device access, callback removal, ETW tampering)
- **4 YARA rules**: high-risk import scanning for driver binaries on disk

### EDR Telemetry Simulator (`lab/EDR-Simulator.ps1`)
Generates synthetic events (JSON + XML) matching detection rule patterns.
8 scenarios: 6 should trigger alerts, 2 baselines that should not.

## Real results (DR_SAPNA workstation, Windows 11 26300)

### Three-axis deep scan (v4 — with handle probe)
| Metric | Value |
|--------|-------|
| Total kernel drivers | 482 |
| Drivers with risk signals | 480 |
| CRITICAL | 1 (`ipt.sys`, score 70) |
| HIGH | 44 |
| MEDIUM | 266 |
| LOW | 169 |
| **User-reachable (THE KEY FINDING)** | **56** |
| LOW tier (sandbox/AppContainer reachable) | 5 |
| MEDIUM tier (standard-user reachable) | 51 |
| Restricted (admin-only) | 6 |
| Unknown ACL | 418 |
| WDAC block rules generated | 2 (non-MS/security CRITICAL/HIGH + reachable) |

### Reachability method comparison (v4 vs v2)
| Method | Reachable found | Note |
|--------|----------------|------|
| ACL analysis (v2 method) | 24 | Registry service Security descriptor |
| Handle probe (v4 NEW) | **32** | CreateFileW zero-access ground truth |
| Confirmed by both | 1 | `vgk.sys` — highest confidence |
| **Total classified** | **62 of 480** (12.9%) | Was 26/482 (5.4%) in v2 |

### Top findings by handle probe (v4 NEW discoveries)
These drivers were classified "Unknown" in v2 and are now confirmed
user-reachable by the CreateFileW handle probe:
- `tcpip.sys` (HIGH 62, PROBE) — the entire TCP/IP stack
- `fltmgr.sys` (HIGH 57, PROBE) — filesystem filter manager
- `ntfs.sys` (HIGH 57, PROBE) — NTFS filesystem driver
- `ndis.sys` (HIGH 57, PROBE) — network driver interface
- `spaceport.sys` (HIGH 57, PROBE) — Storage Spaces
- `peauth.sys` (HIGH 57, PROBE) — Protected Environment Authentication
- `vboxusbmon.sys` (HIGH 52, PROBE) — VirtualBox USB monitor
- `ahcache.sys` (HIGH 57, PROBE) — Application Compatibility Cache

### Gap analysis — what catalogs miss (v4)
| Quadrant | v2 | v4 | Meaning |
|----------|----|----|---------|
| Reachable + high-cap + **uncatalogued** | 18 | **42** | REFEREE's unique value |
| Reachable + catalogued | 0 | 1 | Known overlap |
| Catalogued but restricted | 5 | 4 | Catalog over-triage |

Top gap drivers: `ipt.sys` (CRITICAL, LOW tier), `vgk.sys` (HIGH, LOW tier),
`tcpip.sys` (HIGH, MEDIUM, PROBE), `ntfs.sys` (HIGH, MEDIUM, PROBE),
`fltmgr.sys` (HIGH, MEDIUM, PROBE), `ndis.sys` (HIGH, MEDIUM, PROBE),
`clfs.sys` (HIGH, LOW), `http.sys` (HIGH, MEDIUM).

### Delta (before/after baseline)
Two back-to-back scans: **0 added, 0 removed, 0 changed** — clean baseline,
zero false-positive noise. The compelling story (install a game → quantify
what it added to your kernel attack surface) is the next planned test.

### LOLDrivers cross-reference (702 entries)
| Driver | Category | Hash Match | Use Case |
|--------|----------|------------|----------|
| `afd.sys` | vulnerable driver | NAME_ONLY | Elevate privileges |
| `csc.sys` | vulnerable driver | NAME_ONLY | Elevate privileges |
| `dellinstrumentation.sys` | vulnerable driver | NAME_ONLY | Elevate privileges |
| `ksld.sys` | vulnerable driver | NAME_ONLY | Abuse trusted MS driver |
| `vboxusbmon.sys` | vulnerable driver | NAME_ONLY | Elevate privileges |

All five are NAME_ONLY (filename matches but SHA256 differs) — meaning these are
**patched versions**, not the exact vulnerable binaries. This is exactly the kind
of nuance REFEREE's hash verification adds over filename-only matching.

### Anti-cheat detection
Riot Vanguard (`vgk.sys`) detected: running, boot-start ring-0, valid EV cert
from Riot Games, Inc., device interface `\\.\vgk`. Scored HIGH (65) with
LOW-tier reachability — openable from a sandboxed process.

### Risk by driver category (v4)
| Category | Count | Avg Score | User-Reachable |
|----------|-------|-----------|----------------|
| Anti-Cheat | 1 | 65 | 1 |
| GPU-NVIDIA | 1 | 45 | 0 |
| Virtualization-VBox | 4 | 41 | 2 |
| Security-Defender | 7 | 39.7 | 4 |
| OEM-Dell | 2 | 37.5 | 0 |
| Audio/Network-Realtek | 1 | 35 | 0 |
| Virtualization-HyperV | 6 | 34.2 | 0 |
| GPU-Intel | 9 | 28.6 | 1 |
| OEM-HP | 3 | 28.3 | 0 |
| Microsoft | 431 | 26.4 | 47 |
| Third-Party-Other | 4 | 24.2 | 1 |
| GPU-AMD | 11 | 20.5 | 0 |

## Project layout

```
referee/
  auditor/
    Referee-DeepScan.ps1      # Three-axis deep scanner (the headline tool)
    Referee-Gap.ps1            # Capability x catalog gap analysis
    Referee-Delta.ps1          # Before/after attack-surface diff
    Referee-Fleet.ps1          # Multi-host PSRemoting runner + aggregator
    Referee-DriverDiff.ps1     # Longitudinal / cross-host binary diff
    Referee-Monitor.ps1        # Real-time driver-load watcher (Sysmon/EventLog)
    Referee-WDACValidate.ps1   # WDAC policy build + audit-mode validation
    Referee-Audit.ps1          # Signature-based AC scanner
    Referee-CapScan.ps1        # PE import capability scanner
    Referee-LOLCheck.ps1       # loldrivers.io cross-reference
    Generate-Report.ps1        # HTML dashboard generator
    dashboard.html             # Interactive filterable dashboard (drop JSON)
    signatures.json            # Anti-cheat driver signature DB (9 families)
    loldrivers-simple.json     # Pre-processed LOLDrivers DB (702 entries)
  research/
    analyze.py                 # Reproducible chart + table aggregator
    README.md                  # Dataset schema documentation
    sample-deepscan.json       # Synthetic 12-finding test data
  detections/
    ac-driver-abuse.yml        # Sigma detection rules (4)
    ac-driver-imports.yar      # YARA detection rules (4)
  lab/
    EDR-Simulator.ps1          # Synthetic telemetry generator
    README.md                  # Lab setup and reproduction guide
  disclosure/
    CVD_POLICY.md              # Coordinated disclosure policy
  docs/
    CFP_ABSTRACT.md            # BSides submission abstract
    THREAT_MODEL.md            # Threat model
    PRIMITIVES.md              # Kernel driver risk taxonomy
```

## Ethics and scope

- **Defensive-first:** all tools are read-only auditors and detectors
- **No IOCTLs:** we never send commands to driver interfaces
- **Coordinated disclosure:** vendors notified before any public talk
- **Actionable defense:** every finding ships with a deployable countermeasure
  (WDAC policy, Sigma rule, or YARA rule)

## References

- [loldrivers.io](https://loldrivers.io) - Living Off The Land Drivers
- [Microsoft driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
- MITRE ATT&CK: T1543.003, T1562.001, T1068

## License

Research use. Full license TBD before public release.
