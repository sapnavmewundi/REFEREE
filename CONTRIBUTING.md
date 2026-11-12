# Contributing to REFEREE

Thank you for your interest in REFEREE. We welcome contributions that improve the toolkit's defensive capabilities.

## Scope

REFEREE is a **defensive, read-only** toolkit. All contributions must maintain this principle:

- **No IOCTLs** — we never send commands to driver device interfaces
- **No driver loading** — we never load or inject kernel drivers
- **No exploit primitives** — capability analysis is for defender prioritization, not exploitation
- **No dispatch table extraction** — we analyze imports, not internal driver logic

Contributions that cross these boundaries will not be accepted.

## How to Contribute

### Bug Reports

Open an issue with:
- Windows version and build number
- PowerShell version (`$PSVersionTable.PSVersion`)
- The tool and command you ran
- Expected vs actual behavior
- Sanitized output (remove hostnames/paths if sensitive)

### New Detection Rules

Sigma and YARA rules are welcome. Please:
1. Use correct event sources (see `docs/AUDIT_REPORT.md` for the correct logsource mapping)
2. Include path-based filters to suppress legitimate software
3. Add corresponding test scenarios to `lab/EDR-Simulator.ps1`
4. Test with `sigmac` or `sigma-cli` against the simulator output

### New Device Name Discovery Sources

The handle probe's accuracy depends on discovering device paths. If you know of a discovery method not in our five-source cascade, we want it:
1. Document the source and how it works
2. Add the discovery function to `Referee-DeepScan.ps1`
3. Tag results with the source name for method attribution
4. Test on at least one Windows 10 and one Windows 11 system

### New Driver Categories

The 12-category taxonomy can be extended:
1. Add pattern-match logic to `Get-DriverCategory` in `Referee-DeepScan.ps1`
2. Include signer name and service name patterns
3. Verify against at least 5 real drivers in the category

## Development Setup

```powershell
git clone https://github.com/sapnavmewundi/REFEREE.git
cd REFEREE

# Run the deep scanner (requires Admin)
powershell -ExecutionPolicy Bypass -File auditor\Referee-DeepScan.ps1

# Run the EDR simulator (no Admin needed)
powershell -ExecutionPolicy Bypass -File lab\EDR-Simulator.ps1

# Regenerate research figures
python research\analyze.py research\realdata\deepscan-dr_sapna-v4.json
```

## Code Style

- PowerShell: follow existing patterns (CmdletBinding, proper param blocks, Write-Host with colors)
- Sigma: use [SigmaHQ specification](https://github.com/SigmaHQ/sigma-specification)
- YARA: include `$mz at 0` PE header check for driver rules

## Responsible Disclosure

If your contribution involves a new vulnerability finding in a specific driver, please follow our [Coordinated Disclosure Policy](disclosure/CVD_POLICY.md) before submitting a PR.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
