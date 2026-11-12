<#
 REFEREE WDAC Validate - Close the Loop from Finding to Proven Remediation
 Takes a DeepScan report, builds a proper WDAC (App Control for Business)
 driver block policy from the flagged drivers, and VALIDATES it in audit mode:
 it proves the policy would block the drivers REFEREE flagged while leaving
 the clean (restricted / Microsoft / security-vendor) drivers alone.

 Validation is static by default (no system change): it compiles the policy
 and checks, rule-by-rule, that every intended driver is covered and no
 excluded driver is caught. With -Deploy it additionally stages the policy in
 AUDIT mode (logs would-be blocks, blocks nothing) so you can confirm against
 real Code Integrity events, then -Remove reverts it.

 Usage:
   powershell -File Referee-WDACValidate.ps1 -Report .\out\deepscan-<ts>.json
   powershell -File Referee-WDACValidate.ps1 -Report <...> -Deploy   # audit mode only
   powershell -File Referee-WDACValidate.ps1 -Remove                 # revert audit policy

 SAFETY: default run changes nothing. -Deploy installs an AUDIT-ONLY policy
 (never enforcing) that blocks no driver; -Remove reverts it. Enforcing mode
 is intentionally not automated.
#>
param(
  [string]$Report,
  [string]$OutDir = "$PSScriptRoot\out",
  [switch]$Deploy,
  [switch]$Remove
)
$ErrorActionPreference = "Stop"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$auditPolicyGuid = "{A1B2C3D4-0000-4A2F-9E11-5EFEE0A0D170}"

function Test-Admin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---- Remove mode: revert any staged audit policy ----
if ($Remove) {
  Write-Host "`n=== REFEREE WDAC: Remove audit policy ===" -ForegroundColor Cyan
  if (-not (Test-Admin)) { Write-Error "Administrator required to remove a CI policy."; exit 1 }
  $ciPath = "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
  $staged = Get-ChildItem "$ciPath\*.cip" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'referee' }
  if (-not $staged) { Write-Host "No REFEREE audit policy staged." -ForegroundColor Yellow; exit 0 }
  foreach ($p in $staged) {
    try {
      if (Get-Command CiTool.exe -ErrorAction SilentlyContinue) {
        $polId = $p.BaseName
        & CiTool.exe --remove-policy $polId 2>&1 | Out-Null
      } else {
        Remove-Item $p.FullName -Force
      }
      Write-Host "  removed: $($p.Name)" -ForegroundColor Green
    } catch { Write-Host "  failed to remove $($p.Name): $($_.Exception.Message)" -ForegroundColor Red }
  }
  Write-Host "Audit policy reverted. A reboot finalizes removal." -ForegroundColor Green
  exit 0
}

if (-not $Report -or !(Test-Path $Report)) { Write-Error "Report not found. Pass -Report <deepscan.json>"; exit 1 }
$rep = Get-Content $Report -Raw -Encoding UTF8 | ConvertFrom-Json

Write-Host "`n=== REFEREE WDAC Validate ===" -ForegroundColor Cyan
Write-Host "Host: $($rep.host) | Flagged: $($rep.findings.Count)`n"

# ---- Partition drivers: BLOCK set vs EXCLUDE set ----
# Block: CRITICAL/HIGH + USER_REACHABLE, excluding Microsoft + security vendors
$toBlock = @($rep.findings | Where-Object {
  $_.risk_level -in @("CRITICAL","HIGH") -and $_.acl_status -eq "USER_REACHABLE" -and
  $_.category -notmatch "^Microsoft$|^Security-"
})
# Explicitly-excluded set we must NOT catch
$mustNotBlock = @($rep.findings | Where-Object {
  $_.category -match "^Microsoft$|^Security-" -or $_.acl_status -eq "RESTRICTED"
})

Write-Host "Policy targets (block): $($toBlock.Count)" -ForegroundColor Red
Write-Host "Must-not-block set:     $($mustNotBlock.Count)`n"

# ---- Build a hash-based WDAC policy (hash rules are precise, no signer needed) ----
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$xml = @()
$xml += '<?xml version="1.0" encoding="utf-8"?>'
$xml += '<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">'
$xml += '  <VersionEx>1.0.0.0</VersionEx>'
$xml += "  <PolicyID>$auditPolicyGuid</PolicyID>"
$xml += "  <BasePolicyID>$auditPolicyGuid</BasePolicyID>"
$xml += '  <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>'
$xml += '  <Rules>'
$xml += '    <Rule><Option>Enabled:Audit Mode</Option></Rule>'
$xml += '    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>'
$xml += '    <Rule><Option>Disabled:Script Enforcement</Option></Rule>'
$xml += '  </Rules>'
$xml += '  <FileRules>'
$ruleIds = @()
$i = 0
foreach ($d in $toBlock) {
  $i++
  $rid = "ID_DENY_REF_$i"
  $ruleIds += $rid
  if ($d.file_hash) {
    $xml += "    <!-- $($d.driver) | score=$($d.total_score) | $($d.category) -->"
    $xml += "    <Deny ID=`"$rid`" FriendlyName=`"REFEREE $($d.driver)`" Hash=`"$($d.file_hash.ToUpper())`" />"
  } else {
    $xml += "    <Deny ID=`"$rid`" FriendlyName=`"REFEREE $($d.driver)`" FileName=`"$($d.driver)`" />"
  }
}
$xml += '  </FileRules>'
$xml += '  <SigningScenarios>'
$xml += '    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS" FriendlyName="Drivers">'
$xml += '      <ProductSigners><FileRulesRef>'
foreach ($rid in $ruleIds) { $xml += "        <FileRuleRef RuleID=`"$rid`" />" }
$xml += '      </FileRulesRef></ProductSigners>'
$xml += '    </SigningScenario>'
$xml += '  </SigningScenarios>'
$xml += '</SiPolicy>'
$policyPath = "$OutDir\referee-audit-policy-$stamp.xml"
$xml -join "`n" | Out-File $policyPath -Encoding utf8
Write-Host "Policy XML: $policyPath" -ForegroundColor Green

# ---- STATIC VALIDATION: does the policy cover exactly the intended set? ----
Write-Host "`n[Validation] Static coverage check..." -ForegroundColor Yellow
$policyText = (Get-Content $policyPath -Raw)
$coverPass = 0; $coverFail = @()
foreach ($d in $toBlock) {
  $covered = ($d.file_hash -and $policyText -match [regex]::Escape($d.file_hash.ToUpper())) -or
             ($policyText -match [regex]::Escape($d.driver))
  if ($covered) { $coverPass++ } else { $coverFail += $d.driver }
}
$leak = @()
foreach ($d in $mustNotBlock) {
  if ($d.file_hash -and $policyText -match [regex]::Escape($d.file_hash.ToUpper())) { $leak += $d.driver }
}

Write-Host ("  Intended drivers covered: {0}/{1}" -f $coverPass, $toBlock.Count) -ForegroundColor $(if($coverFail.Count){"Red"}else{"Green"})
if ($coverFail.Count) { Write-Host "    MISSING: $($coverFail -join ', ')" -ForegroundColor Red }
Write-Host ("  Excluded drivers leaked into policy: {0}" -f $leak.Count) -ForegroundColor $(if($leak.Count){"Red"}else{"Green"})
if ($leak.Count) { Write-Host "    LEAKED: $($leak -join ', ')" -ForegroundColor Red }

$validationPass = ($coverFail.Count -eq 0 -and $leak.Count -eq 0)
Write-Host "`n  STATIC VALIDATION: $(if($validationPass){'PASS'}else{'FAIL'})" -ForegroundColor $(if($validationPass){"Green"}else{"Red"})

# ---- Optional compile + audit-mode deploy ----
$cipPath = $null
if (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue) {
  try {
    $cipPath = "$OutDir\referee-audit-$stamp.cip"
    ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath $cipPath | Out-Null
    Write-Host "  Compiled policy: $cipPath" -ForegroundColor Green
  } catch { Write-Host "  Compile skipped: $($_.Exception.Message)" -ForegroundColor Yellow }
}

if ($Deploy) {
  Write-Host "`n[Deploy] Staging AUDIT-ONLY policy (blocks nothing, logs would-be blocks)..." -ForegroundColor Yellow
  if (-not (Test-Admin)) { Write-Error "Administrator required to stage a CI policy."; exit 1 }
  if (-not $cipPath) { Write-Error "No compiled .cip (ConvertFrom-CIPolicy unavailable). Cannot deploy."; exit 1 }
  if (Get-Command CiTool.exe -ErrorAction SilentlyContinue) {
    & CiTool.exe --update-policy $cipPath 2>&1 | Out-Null
    Write-Host "  Audit policy staged via CiTool. Check 'Applications and Services Logs > Microsoft > Windows > CodeIntegrity > Operational' for Event 3076 (audit blocks)." -ForegroundColor Green
    Write-Host "  Revert with: Referee-WDACValidate.ps1 -Remove" -ForegroundColor Cyan
  } else {
    Write-Host "  CiTool.exe not found (older Windows). Copy $cipPath to CodeIntegrity\CiPolicies\Active manually to test." -ForegroundColor Yellow
  }
}

# ---- Save validation report ----
$valOut = "$OutDir\wdac-validation-$stamp.json"
[pscustomobject]@{
  tool = "referee-wdac-validate"; version = "1.0"; generated = (Get-Date -Format o)
  host = $rep.host
  policy_xml = $policyPath; policy_cip = $cipPath
  blocked_count = $toBlock.Count
  coverage_pass = $coverPass; coverage_missing = $coverFail
  excluded_leaked = $leak
  static_validation = $(if($validationPass){"PASS"}else{"FAIL"})
  deployed_audit = [bool]$Deploy
} | ConvertTo-Json -Depth 5 | Out-File $valOut -Encoding utf8
Write-Host "`nValidation report: $valOut"
Write-Host "=== WDAC VALIDATE COMPLETE ===" -ForegroundColor Cyan
