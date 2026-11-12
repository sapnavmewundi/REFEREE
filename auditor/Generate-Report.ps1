<#
 REFEREE Report Dashboard Generator
 Reads capscan JSON output and generates a self-contained HTML dashboard.
 Usage: powershell -ExecutionPolicy Bypass -File Generate-Report.ps1 [-JsonPath path]
#>
param(
  [string]$JsonPath = "",
  [string]$OutDir = "$PSScriptRoot\out"
)
$ErrorActionPreference = "Stop"

if (-not $JsonPath) {
  $latest = Get-ChildItem "$OutDir\capscan-*.json" | Sort-Object Name | Select-Object -Last 1
  if (-not $latest) { Write-Error "No capscan JSON found in $OutDir"; exit 1 }
  $JsonPath = $latest.FullName
}
Write-Host "Reading: $JsonPath"
$raw = Get-Content $JsonPath -Raw -Encoding UTF8
if ($raw[0] -eq [char]0xFEFF) { $raw = $raw.Substring(1) }
$data = $raw | ConvertFrom-Json

$total = $data.total_drivers
$flagged = $data.flagged
$stats = $data.stats
$findings = $data.findings | Sort-Object risk_score -Descending

# Build table rows
$rows = ""
foreach ($f in $findings) {
  if ($f.risk_score -lt 25) { continue }
  $cls = switch ($f.risk_level) {
    "CRITICAL" { "crit" }
    "HIGH"     { "high" }
    "MEDIUM"   { "med" }
    default    { "low" }
  }
  $abuse = if ($f.abuse_known) { "YES" } else { "-" }
  $ac = if ($f.ac_product) { $f.ac_product } else { "-" }
  $rows += "<tr class=`"$cls`"><td>$($f.driver)</td><td>$($f.state)</td><td><span class=`"badge $cls`">$($f.risk_level)</span></td><td>$($f.risk_score)</td><td class=`"api`">$($f.cat_A_mem)</td><td class=`"api`">$($f.cat_B_proc)</td><td class=`"api`">$($f.cat_C_cb)</td><td>$abuse</td><td>$ac</td></tr>`n"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REFEREE - Kernel Driver Risk Dashboard</title>
<style>
:root {
  --bg: #0a0a0f;
  --surface: #12121a;
  --border: #1e1e2e;
  --text: #e0e0e8;
  --muted: #888899;
  --crit-bg: #3d0a0a;
  --crit: #ff4444;
  --high-bg: #3d2a0a;
  --high: #ff8844;
  --med-bg: #3d3d0a;
  --med: #ffcc44;
  --accent: #00ccff;
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: 'Segoe UI', -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  padding: 24px;
}
.header {
  display: flex;
  align-items: baseline;
  gap: 16px;
  margin-bottom: 8px;
}
.header h1 { font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }
.header h1 span { color: var(--accent); }
.subtitle { color: var(--muted); font-size: 14px; margin-bottom: 32px; }

.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}
.card .num { font-size: 36px; font-weight: 700; }
.card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
.card.crit .num { color: var(--crit); }
.card.high .num { color: var(--high); }
.card.med .num { color: var(--med); }
.card.accent .num { color: var(--accent); }

.bar-section { margin-bottom: 32px; }
.bar-section h2 { font-size: 16px; font-weight: 600; margin-bottom: 12px; }
.bar-track {
  background: var(--surface);
  border-radius: 6px;
  height: 32px;
  display: flex;
  overflow: hidden;
  border: 1px solid var(--border);
}
.bar-seg { display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:600; color:#fff; min-width:40px; }
.bar-seg.crit { background: var(--crit); }
.bar-seg.high { background: var(--high); color:#000; }
.bar-seg.med { background: var(--med); color:#000; }
.bar-seg.clean { background: #2a2a3a; color: var(--muted); }

.legend { display:flex; gap:16px; margin-top:8px; font-size:12px; color:var(--muted); }
.legend span::before { content:''; display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:4px; vertical-align:middle; }
.legend .l-crit::before { background:var(--crit); }
.legend .l-high::before { background:var(--high); }
.legend .l-med::before { background:var(--med); }
.legend .l-clean::before { background:#2a2a3a; }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead { position: sticky; top: 0; }
th {
  background: var(--surface);
  border-bottom: 2px solid var(--border);
  padding: 10px 8px;
  text-align: left;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--muted);
}
td { padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
td.api { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11px; color: var(--muted); word-break: break-all; max-width: 200px; }
tr.crit { background: var(--crit-bg); }
tr.high { background: var(--high-bg); }
tr.med { background: var(--med-bg); }
tr:hover { opacity: 0.9; }

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
}
.badge.crit { background: var(--crit); color: #fff; }
.badge.high { background: var(--high); color: #000; }
.badge.med { background: var(--med); color: #000; }

.table-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }
h2 { font-size: 16px; font-weight: 600; margin-bottom: 12px; }

.footer { margin-top: 32px; font-size: 12px; color: var(--muted); text-align: center; }
</style>
</head>
<body>
<div class="header">
  <h1><span>REFEREE</span> Kernel Driver Risk Dashboard</h1>
</div>
<div class="subtitle">Host: $($data.host) | Generated: $($data.generated) | Scan: Capability Scanner v0.2</div>

<div class="cards">
  <div class="card accent"><div class="num">$total</div><div class="label">Total Drivers</div></div>
  <div class="card accent"><div class="num">$flagged</div><div class="label">Flagged</div></div>
  <div class="card crit"><div class="num">$($stats.critical)</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">$($stats.high)</div><div class="label">High</div></div>
  <div class="card med"><div class="num">$($stats.medium)</div><div class="label">Medium</div></div>
</div>

<div class="bar-section">
  <h2>Driver Risk Distribution</h2>
  <div class="bar-track">
    <div class="bar-seg crit" style="width:$(([math]::Round($stats.critical/$total*100,1)))%">$($stats.critical)</div>
    <div class="bar-seg high" style="width:$(([math]::Round($stats.high/$total*100,1)))%">$($stats.high)</div>
    <div class="bar-seg med" style="width:$(([math]::Round($stats.medium/$total*100,1)))%">$($stats.medium)</div>
    <div class="bar-seg clean" style="width:$(([math]::Round(($total - $flagged)/$total*100,1)))%">$($total - $flagged)</div>
  </div>
  <div class="legend">
    <span class="l-crit">Critical ($($stats.critical))</span>
    <span class="l-high">High ($($stats.high))</span>
    <span class="l-med">Medium ($($stats.medium))</span>
    <span class="l-clean">Clean ($($total - $flagged))</span>
  </div>
</div>

<h2>Risk Leaderboard (MEDIUM and above)</h2>
<div class="table-wrap">
<table>
<thead>
<tr><th>Driver</th><th>State</th><th>Risk</th><th>Score</th><th>Memory APIs (Cat A)</th><th>Process APIs (Cat B)</th><th>Callback APIs (Cat C)</th><th>Abuse Known</th><th>AC Product</th></tr>
</thead>
<tbody>
$rows
</tbody>
</table>
</div>

<div class="footer">
  REFEREE - Defensive kernel driver risk assessment | github.com/referee-project/referee
</div>
</body>
</html>
"@

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outFile = "$OutDir\dashboard-$stamp.html"
$html | Out-File $outFile -Encoding utf8
Write-Host "`nDashboard: $outFile"
Write-Host "Open it in a browser to see the visual report.`n"
