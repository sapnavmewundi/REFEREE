# REFEREE — CFP Abstract (BSidesSF 2027)

## Title

REFEREE: Your Anti-Cheat Is the Rootkit — Systematic Reachability Analysis of Kernel Driver Attack Surface

## Abstract

Every gamer on the planet voluntarily installs a signed, Microsoft-trusted ring-0 kernel driver that every AV and EDR whitelists on sight. Anti-cheat engines, GPU shims, OEM helpers — hundreds of drivers sit at the highest privilege level on a stock Windows box, and the security industry's only question has been *"is this one on the naughty list?"* We asked a different question: **who can actually open a handle to each of these drivers, and what god-mode primitives does that hand them?**

The answer was worse than we expected.

We present **REFEREE**, a three-axis methodology and open-source toolkit that moves driver risk assessment from catalog lookups to ground-truth reachability:

1. **Capability** — PE import scanning for memory-access, cross-process manipulation, and callback-removal APIs. Not "does this driver import something scary" but "which specific kernel primitives does it expose?"
2. **Reachability** — five device-name discovery sources (registry DeviceMap, device interface classes, IoCreateDevice conventions, 70+ known driver-to-device mappings, service Parameters keys) fed into a zero-access `CreateFileW` handle probe. Every discovered device path is opened at `FILE_READ_ATTRIBUTES` — read-only, no IOCTLs — to give a definitive yes/no: can an unprivileged process reach this driver? Results are classified by integrity tier: **LOW** (reachable from a sandboxed/AppContainer process) vs **MEDIUM** (standard-user token).
3. **Known vulnerability** — loldrivers.io cross-reference with SHA256 hash verification, because a filename match on a patched binary is not a finding.

### The numbers

We scanned **482 kernel drivers** on a live Windows 11 workstation. ACL descriptor analysis — the method every existing tool uses — found 24 user-reachable drivers. Our handle probe found **56** — a **133% increase**. More than half of the reachable attack surface was invisible to the only technique anyone was using.

The probe uncovered handles to drivers nobody expected an unprivileged process to reach: `tcpip.sys` (the entire TCP/IP stack), `ntfs.sys` (the filesystem), `fltmgr.sys` (filter manager), `ndis.sys` (network interface), and 28 others — all classified "Unknown" by ACL-only analysis, all confirmed reachable by ground-truth probing.

Five of those 56 are reachable from a **sandboxed process** — LOW-tier, the worst possible finding. One is Riot Vanguard (`vgk.sys`): a boot-start anti-cheat driver with an EV cert, importing process-manipulation and callback-removal APIs, openable from inside an AppContainer sandbox.

### The gap nobody is talking about

Gap analysis revealed **42 reachable, high-capability drivers** that **loldrivers.io does not list** — attack surface that catalog-only triage misses entirely. Conversely, 4 catalogued "known-bad" drivers turned out to be admin-only on this box — catalog over-triage that wastes analyst time. The catalog covers 1 of the 56 reachable drivers. REFEREE covers the other 55.

### What we ship

Beyond the core scanner, REFEREE is a **10-tool defensive suite** — every finding ships with a deployable countermeasure:

| Tool | What it does |
|------|-------------|
| **DeepScan** | Three-axis scanner with handle probe — the headline tool |
| **Attack-surface delta** | Snapshot before/after a software install, quantify what it added to your kernel attack surface |
| **Gap analysis** | Capability × catalog matrix proving what catalogs miss |
| **Fleet runner** | Scan N machines over PSRemoting, surface config-drift drivers |
| **Longitudinal diffing** | Same driver across hosts/time — catch signer changes and cosmetic "updates" |
| **Real-time monitor** | Sysmon/EventLog watcher scoring new driver loads as they happen |
| **WDAC validate** | Build a hash-based block policy, prove static coverage, stage in audit-only mode |
| **Interactive dashboard** | Dark-themed, filterable, runs entirely in-browser |
| **Sigma + YARA pack** | 4 Sigma rules + 4 YARA rules for driver abuse pattern detection |
| **Research pipeline** | Deterministic chart/table generation from JSON reports |

Every tool is read-only. We never send IOCTLs. We never load drivers. This is a defensive audit toolkit, not an exploit framework.

## Outline

1. **The trust assumption** — why signed drivers get a free pass from every defensive product on the endpoint, and why that trust model is broken
2. **Three-axis methodology** — from "scary import list" to "actually reachable attack surface": how reachability changes the risk picture
3. **The handle probe** — five device-name discovery sources, zero-access CreateFileW, and why ACL analysis alone misses 57% of reachable drivers
4. **Reachability depth** — LOW-tier vs MEDIUM-tier and why a sandbox-reachable driver is a bigger finding than a standard-user one
5. **Gap analysis** — the 42 drivers catalogs miss, the 4 they over-flag, and what this means for catalog-dependent triage
6. **Live demo** — run the deep scanner against the audience's own machine config, show the reachability map, install a game on stage, run the delta, generate a block policy
7. **Fleet-scale** — config-drift detection, longitudinal tracking, and the drivers that are reachable on some boxes but not others
8. **Tool release** — REFEREE as an open-source defensive toolkit: audit your fleet, deploy detections, generate WDAC policies, monitor continuously
9. **Responsible disclosure** — timeline and vendor engagement
10. **Recommendations** — for Microsoft, anti-cheat vendors, and enterprise defenders

## Key Contributions

- First systematic, published reachability analysis of kernel driver device objects on consumer Windows — combining ACL descriptor analysis with ground-truth handle probing across five device-name discovery sources
- Empirical proof that ACL-only analysis misses 57% of the reachable attack surface (24 vs 56 drivers)
- Reachability depth classification (LOW/MEDIUM integrity tier) — first published taxonomy of driver reachability by process integrity level
- Gap analysis proving catalog-only approaches miss 42 of 56 reachable high-capability drivers on a real workstation — the strongest published evidence that loldrivers.io alone is insufficient for driver triage
- Three-axis risk scoring methodology (capability × reachability × known vuln) with 12-category driver taxonomy
- Open-source 10-tool defensive suite with actionable outputs: WDAC policies, Sigma/YARA rules, fleet aggregation, continuous monitoring
- All results from a real Windows 11 workstation with real drivers — no synthetic data, no lab setups

## Format

40-minute talk + open-source tool release

## Speaker Bio

*[To be filled]*

## CFP Hook

"We audited every kernel driver on a Windows box — not just what they can do, but who can talk to them. The only method anyone uses found 24 reachable drivers. We found 56. The other 32 — including the TCP/IP stack, the filesystem driver, and a sandboxed-process-reachable anti-cheat engine — were invisible. Catalogs cover 1 of the 56. We cover the other 55."
