# engine/enforcement/mdo_safe_attachments_enforcer.py
from __future__ import annotations

import json
import subprocess
from typing import Tuple

from engine.enforcement.registry import register


def _run_powershell(script: str) -> Tuple[int, str, str]:
    """
    Runs PowerShell using pwsh (preferred) or powershell.
    Returns (exit_code, stdout, stderr)
    """
    for exe in ("pwsh", "powershell"):
        try:
            p = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                timeout=180,
            )
            return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
        except FileNotFoundError:
            continue
    raise RuntimeError("Neither pwsh nor powershell is available on this system")

def _mdo_safe_attachments_block_action(**kwargs):
    tenant = kwargs["tenant"]
    approval = kwargs.get("approval") or {}
    mode = (kwargs.get("mode") or "report-only").lower()

    if mode == "enforce" and approval.get("approved") is not True:
        return (
            "NOT_EVALUATED",
            "APPROVAL_REQUIRED",
            "Approval required to change Safe Attachments action to Block",
            {},
            409,
        )

    exo = tenant.get("exoPowershell") or {}
    if not (exo.get("appId") and exo.get("certificateThumbprint") and exo.get("organization")):
        return (
            "ERROR",
            "MISSING_PREREQUISITE",
            "Missing Exchange Online PowerShell configuration",
            {},
            424,
        )

    ps = f'''
Connect-ExchangeOnline -AppId "{exo["appId"]}" `
  -CertificateThumbprint "{exo["certificateThumbprint"]}" `
  -Organization "{exo["organization"]}" `
  -ShowBanner:$false

$policy = Get-SafeAttachmentPolicy |
  Where-Object {{ $_.Name -eq "ATLAS Safe Attachments Policy" }} |
  Select-Object -First 1

if (-not $policy) {{
  @{{
    action = "missing_atlas_policy"
    compliant = $false
  }} | ConvertTo-Json
  exit
}}

if ($policy.Action -eq "Block") {{
  @{{
    action = "no_change"
    compliant = $true
  }} | ConvertTo-Json
  exit
}}

if ("{mode}" -ne "enforce") {{
  @{{
    action = "report_only_drift"
    compliant = $false
    currentAction = $policy.Action
    desiredAction = "Block"
  }} | ConvertTo-Json
  exit
}}

Set-SafeAttachmentPolicy -Identity $policy.Identity -Action Block

$after = Get-SafeAttachmentPolicy -Identity $policy.Identity

@{{
  action = "set_policy_properties"
  compliant = ($after.Action -eq "Block")
  beforeAction = $policy.Action
  afterAction = $after.Action
}} | ConvertTo-Json
'''

    from subprocess import run

    result = run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return (
            "ERROR",
            "ENFORCER_ERROR",
            "PowerShell execution failed",
            {"stderr": result.stderr},
            500,
        )

    import json
    data = json.loads(result.stdout)

    action = data.get("action")
    compliant = data.get("compliant", False)

    if mode != "enforce":
        return (
            ("COMPLIANT" if compliant else "DRIFTED"),
            "REPORT_ONLY_EVALUATED",
            "Safe Attachments action evaluated",
            data,
            200,
        )

    return (
        ("COMPLIANT" if compliant else "DRIFTED"),
        "ENFORCER_EXECUTED",
        "Safe Attachments action enforced",
        data,
        200,
    )

def _enforce_mdo_safe_attachments(**kwargs) -> tuple[str, str, str, dict, int]:
    tenant = kwargs["tenant"]
    approval = kwargs.get("approval") or {}
    mode = (kwargs.get("mode") or "report-only").strip().lower()

    exo = (tenant or {}).get("exoPowershell") or {}
    if not exo:
        return (
            "ERROR",
            "MISSING_PREREQUISITE",
            "Missing exoPowershell configuration in tenant JSON",
            {"expectedTenantField": "exoPowershell"},
            424,
        )

    app_id = exo.get("appId")
    thumb = exo.get("certificateThumbprint")
    org = exo.get("organization")
    if not (app_id and thumb and org):
        return (
            "ERROR",
            "MISSING_PREREQUISITE",
            "exoPowershell config incomplete",
            {"expected": ["appId", "certificateThumbprint", "organization"], "exoPowershell": exo},
            424,
        )

    # Approval gate for enforce mode
    if mode == "enforce" and approval.get("approved") is not True:
        return (
            "NOT_EVALUATED",
            "APPROVAL_REQUIRED",
            "Missing approval file or approved=false for enforce",
            {"requiredApprovalField": "approved", "mode": mode},
            409,
        )

    ps = fr"""
$ErrorActionPreference = "Stop"
$WarningPreference = "SilentlyContinue"

Import-Module ExchangeOnlineManagement

$AppId = "{app_id}"
$Thumb = "{thumb}"
$Org = "{org}"
$Mode = "{mode}"

try {{ Import-Module ExchangeOnlineManagement -ErrorAction Stop }} catch {{}}

Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $Thumb -Organization $Org -ShowBanner:$false | Out-Null

function Snapshot() {{
  $pol = @(
    Get-SafeAttachmentPolicy -ErrorAction Stop |
      Select-Object Name,Enable,Action,IsBuiltInProtection,IsValid,Identity
  )
  $rules = @(
    Get-SafeAttachmentRule -ErrorAction Stop |
      Select-Object Name,State,SafeAttachmentPolicy,Priority,Identity
  )
  return [PSCustomObject]@{{
    policyCount = $pol.Count
    ruleCount   = $rules.Count
    policies    = $pol
    rules       = $rules
  }}
}}

try {{
  $before = Snapshot

  $enabled = @($before.rules | Where-Object {{ $_.State -eq "Enabled" }})
  if ($enabled.Count -ge 1) {{
    $out = [PSCustomObject]@{{
      mode      = $Mode
      compliant = $true
      action    = "no_change"
      before    = $before
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }}

  if ($Mode -ne "enforce") {{
    $out = [PSCustomObject]@{{
      mode      = $Mode
      compliant = $false
      action    = "report_only_drift"
      before    = $before
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }}

  # enforce-mode from here down

  if ($before.ruleCount -eq 0) {{
    $baselineRuleName = "ATLAS Baseline SafeAttachments"

    # Determine target policy (never mutate built-in protection)
    $targetPolicy = $null
    $custom = @($before.policies | Where-Object {{ $_.IsBuiltInProtection -eq $false }} | Select-Object -First 1)
    if ($custom.Count -ge 1) {{
      $targetPolicy = $custom[0]
    }}

    # Create ATLAS policy if none exists
    if (-not $targetPolicy) {{
      $atlasPolicyName = "ATLAS Safe Attachments Policy"
      $createPolicyError = $null
      try {{
        # Tier-3 safe baseline: enable scanning and use DynamicDelivery (least disruptive)
        New-SafeAttachmentPolicy -Name $atlasPolicyName -Enable $true -Action DynamicDelivery -ErrorAction Stop | Out-Null
      }} catch {{
        $createPolicyError = ($_ | Out-String)
      }}

      $targetPolicy = Get-SafeAttachmentPolicy |
        Where-Object {{ $_.Name -eq $atlasPolicyName }} |
        Select-Object -First 1

      if (-not $targetPolicy -and $createPolicyError) {{
        $out = [PSCustomObject]@{{
          mode         = $Mode
          compliant    = $false
          action       = "blocked_no_rules"
          reasonCode   = "CREATION_FAILED"
          reasonDetail = "Failed to create ATLAS Safe Attachments policy: $createPolicyError"
          before       = $before
        }}
        $out | ConvertTo-Json -Depth 10
        exit 0
      }}
    }}

    if (-not $targetPolicy -or -not $targetPolicy.Identity) {{
      $out = [PSCustomObject]@{{
        mode         = $Mode
        compliant    = $false
        action       = "blocked_no_rules"
        reasonCode   = "MISSING_SIGNAL"
        reasonDetail = "No usable Safe Attachments policy identity available for baseline enforcement."
        before       = $before
      }}
      $out | ConvertTo-Json -Depth 10
      exit 0
    }}

    New-SafeAttachmentRule -Name $baselineRuleName -SafeAttachmentPolicy $targetPolicy.Identity -RecipientDomainIs @("*") -Priority 0 -ErrorAction Stop | Out-Null

    $after = Snapshot
    $enabledAfter = @($after.rules | Where-Object {{ $_.State -eq "Enabled" }})

    $out = [PSCustomObject]@{{
      mode            = $Mode
      action          = "created_baseline_rule"
      compliant       = ($enabledAfter.Count -ge 1)
      createdRuleName = $baselineRuleName
      targetPolicy    = $targetPolicy.Name
      before          = $before
      after           = $after
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }}

  if ($before.ruleCount -gt 1) {{
    $out = [PSCustomObject]@{{
      mode         = $Mode
      compliant    = $false
      action       = "blocked_multiple_rules"
      reasonCode   = "UNSUPPORTED_MODE"
      reasonDetail = "Multiple Safe Attachments rules exist and none are enabled; manual selection required."
      before       = $before
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }}

  # ruleCount == 1, none enabled -> enable the single rule
  $r = $before.rules | Select-Object -First 1
  try {{
    Set-SafeAttachmentRule -Identity $r.Identity -State Enabled -ErrorAction Stop | Out-Null
  }} catch {{
    try {{
      Set-SafeAttachmentRule -Identity $r.Name -State Enabled -ErrorAction Stop | Out-Null
    }} catch {{
      throw
    }}
  }}

  $after = Snapshot
  $enabledAfter = @($after.rules | Where-Object {{ $_.State -eq "Enabled" }})

  $out = [PSCustomObject]@{{
    mode      = $Mode
    action    = "enabled_single_rule"
    compliant = ($enabledAfter.Count -ge 1)
    before    = $before
    after     = $after
  }}
  $out | ConvertTo-Json -Depth 10
}}
finally {{
  try {{ Disconnect-ExchangeOnline -Confirm:$false | Out-Null }} catch {{}}
}}
"""

    code, stdout, stderr = _run_powershell(ps)
    if code != 0:
        return (
            "ERROR",
            "ENFORCER_ERROR",
            "PowerShell execution failed for MDOSafeAttachments",
            {"stderr": stderr, "stdout": stdout},
            500,
        )

    try:
        result = json.loads(stdout) if stdout else {}
    except Exception:
        return (
            "ERROR",
            "ENFORCER_ERROR",
            "Failed to parse PowerShell JSON output",
            {"raw_stdout": stdout, "raw_stderr": stderr},
            500,
        )

    action = result.get("action")
    compliant = bool(result.get("compliant"))

    if action in ("blocked_multiple_rules", "blocked_no_rules"):
        return (
            "NOT_EVALUATED",
            result.get("reasonCode") or "UNSUPPORTED_MODE",
            result.get("reasonDetail") or "Enforcement blocked by safety rules",
            {"result": result},
            409,
        )

    if mode != "enforce":
        if compliant:
            return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: safe attachments rule enabled", {"result": result}, 200)
        return ("DRIFTED", "REPORT_ONLY_EVALUATED", "Report-only: no enabled safe attachments rules found", {"result": result}, 200)

    if compliant:
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforcer executed; safe attachments rule enabled/verified", {"result": result}, 200)
    return ("DRIFTED", "ENFORCER_EXECUTED", "Enforcer executed but verification did not show enabled rule", {"result": result}, 200)


register("MDOSafeAttachments", _enforce_mdo_safe_attachments)
register("MDOSafeAttachmentsBlockAction", _mdo_safe_attachments_block_action)
