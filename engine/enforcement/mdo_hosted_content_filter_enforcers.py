# engine/enforcement/mdo_hosted_content_filter_enforcers.py
from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, Tuple

from engine.enforcement.registry import register

# ---- helpers ----

def _run_powershell(script: str) -> Tuple[int, str, str]:
    for exe in ("pwsh", "powershell"):
        try:
            p = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                timeout=240,
            )
            return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
        except FileNotFoundError:
            continue
    raise RuntimeError("Neither pwsh nor powershell is available on this system")


def _get_exo_config(tenant: dict) -> Tuple[str, str, str] | None:
    exo = (tenant or {}).get("exoPowershell") or {}
    app_id = exo.get("appId")
    thumb = exo.get("certificateThumbprint")
    org = exo.get("organization")
    if not (app_id and thumb and org):
        return None
    return app_id, thumb, org


# ---- core runner: enforce ONE property on HostedContentFilterPolicy ----

def _enforce_hcf_property(
    *,
    tenant: dict,
    approval: dict,
    mode: str,
    control_id: str,
    property_name: str,
    desired_value: Any,
) -> tuple[str, str, str, dict, int]:
    mode = (mode or "report-only").strip().lower()

    exo_cfg = _get_exo_config(tenant)
    if not exo_cfg:
        return ("ERROR", "MISSING_PREREQUISITE", "Missing/incomplete exoPowershell config", {}, 424)

    if mode == "enforce" and approval.get("approved") is not True:
        return ("NOT_EVALUATED", "APPROVAL_REQUIRED", "Approval required for enforce mode", {"controlId": control_id}, 409)

    app_id, thumb, org = exo_cfg

    # NOTE: We keep stdout JSON-only: WarningPreference must be SilentlyContinue
    ps = fr"""
$ErrorActionPreference = "Stop"
$WarningPreference = "SilentlyContinue"

Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -AppId "{app_id}" -CertificateThumbprint "{thumb}" -Organization "{org}" -ShowBanner:$false | Out-Null

$Mode = "{mode}"
$Property = "{property_name}"
$Desired = "{desired_value}"

function Snapshot() {{
  $pol = @(
    Get-HostedContentFilterPolicy -ErrorAction Stop |
      Select-Object Name,IsDefault,Identity,BulkSpamAction,HighConfidenceSpamAction,PhishSpamAction,SpamAction
  )
  $rules = @(
    Get-HostedContentFilterRule -ErrorAction Stop |
      Select-Object Name,State,HostedContentFilterPolicy,Priority,Identity
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

  # Determine target policy (Tier-3 safe, deterministic):
  # - prefer existing non-default policy if there is exactly one
  # - else if only default exists, create ATLAS policy + baseline rule
  $custom = @($before.policies | Where-Object {{ $_.IsDefault -eq $false }})
  $target = $null

  if ($custom.Count -eq 1) {{
    $target = $custom[0]
  }} elseif ($custom.Count -gt 1) {{
    $out = [PSCustomObject]@{{
      mode         = $Mode
      action       = "blocked_multiple_custom_policies"
      compliant    = $false
      reasonCode   = "UNSUPPORTED_MODE"
      reasonDetail = "Multiple non-default HostedContentFilter policies exist; cannot deterministically choose one."
      before       = $before
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }} else {{
    # no custom policies
    if ($Mode -ne "enforce") {{
      $out = [PSCustomObject]@{{
        mode      = $Mode
        action    = "report_only_no_custom_policy"
        compliant = $false
        before    = $before
      }}
      $out | ConvertTo-Json -Depth 10
      exit 0
    }}

    $atlasPolicyName = "ATLAS AntiSpam Policy"
    $createErr = $null
    try {{
      New-HostedContentFilterPolicy -Name $atlasPolicyName -ErrorAction Stop | Out-Null
    }} catch {{
      $createErr = ($_ | Out-String)
    }}

    $target = Get-HostedContentFilterPolicy | Where-Object {{ $_.Name -eq $atlasPolicyName }} | Select-Object -First 1
    if (-not $target -and $createErr) {{
      $out = [PSCustomObject]@{{
        mode         = $Mode
        action       = "blocked_policy_create_failed"
        compliant    = $false
        reasonCode   = "CREATION_FAILED"
        reasonDetail = "Failed creating ATLAS AntiSpam Policy: $createErr"
        before       = $before
      }}
      $out | ConvertTo-Json -Depth 10
      exit 0
    }}

    # Ensure a baseline rule exists so the policy is actually applied tenant-wide
    $ruleName = "ATLAS Baseline AntiSpam"
    $existingRule = Get-HostedContentFilterRule | Where-Object {{ $_.Name -eq $ruleName }} | Select-Object -First 1
    if (-not $existingRule -and $target -and $target.Identity) {{
      New-HostedContentFilterRule -Name $ruleName -HostedContentFilterPolicy $target.Identity -RecipientDomainIs @("*") -Priority 0 -ErrorAction Stop | Out-Null
    }}
  }}

  if (-not $target -or -not $target.Identity) {{
    $out = [PSCustomObject]@{{
      mode         = $Mode
      action       = "blocked_no_target_policy"
      compliant    = $false
      reasonCode   = "MISSING_SIGNAL"
      reasonDetail = "No usable HostedContentFilter policy identity found."
      before       = $before
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }}

  # Compare current value
  $current = $null
  try {{
    $current = ($before.policies | Where-Object {{ $_.Identity -eq $target.Identity }} | Select-Object -First 1).$Property
  }} catch {{}}

  if ($current -eq $Desired) {{
    $out = [PSCustomObject]@{{
      mode      = $Mode
      action    = "no_change"
      compliant = $true
      target    = $target.Name
      property  = $Property
      value     = $current
      before    = $before
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }}

  if ($Mode -ne "enforce") {{
    $out = [PSCustomObject]@{{
      mode      = $Mode
      action    = "report_only_drift"
      compliant = $false
      target    = $target.Name
      property  = $Property
      current   = $current
      desired   = $Desired
      before    = $before
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }}

  # Enforce property on the policy
  $params = @{{ Identity = $target.Identity }}
  $params[$Property] = $Desired

  Set-HostedContentFilterPolicy @params -ErrorAction Stop | Out-Null

  $after = Snapshot
  $afterVal = ($after.policies | Where-Object {{ $_.Identity -eq $target.Identity }} | Select-Object -First 1).$Property

  $out = [PSCustomObject]@{{
    mode      = $Mode
    action    = "set_policy_property"
    compliant = ($afterVal -eq $Desired)
    target    = $target.Name
    property  = $Property
    beforeVal = $current
    afterVal  = $afterVal
    desired   = $Desired
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
        return ("ERROR", "ENFORCER_ERROR", "PowerShell failed", {"stderr": stderr, "stdout": stdout}, 500)

    try:
        result = json.loads(stdout) if stdout else {}
    except Exception:
        return ("ERROR", "ENFORCER_ERROR", "Failed to parse PowerShell JSON", {"raw_stdout": stdout, "raw_stderr": stderr}, 500)

    action = result.get("action")
    compliant = bool(result.get("compliant"))

    if action and action.startswith("blocked_"):
        return (
            "NOT_EVALUATED",
            result.get("reasonCode") or "UNSUPPORTED_MODE",
            result.get("reasonDetail") or "Enforcement blocked by safety rules",
            {"result": result},
            409,
        )

    if mode != "enforce":
        return (
            ("COMPLIANT" if compliant else "DRIFTED"),
            "REPORT_ONLY_EVALUATED",
            "Report-only evaluation complete",
            {"result": result},
            200,
        )

    return (
        ("COMPLIANT" if compliant else "DRIFTED"),
        "ENFORCER_EXECUTED",
        "Enforcer executed",
        {"result": result},
        200,
    )


# ---- register concrete controls ----

def _bulk_spam_action(**kwargs):
    return _enforce_hcf_property(
        tenant=kwargs["tenant"],
        approval=kwargs.get("approval") or {},
        mode=kwargs.get("mode") or "report-only",
        control_id="MDOBulkSpamAction",
        property_name="BulkSpamAction",
        desired_value="MoveToJmf",
    )

def _bulk_complaint_level_threshold(**kwargs):
    return _enforce_hcf_property(
        tenant=kwargs["tenant"],
        approval=kwargs.get("approval") or {},
        mode=kwargs.get("mode") or "report-only",
        control_id="MDOBulkSpamAction",
        property_name="BulkSpamAction",
        desired_value="MoveToJmf",
    )
def _high_conf_spam_action(**kwargs):
    return _enforce_hcf_property(
        tenant=kwargs["tenant"],
        approval=kwargs.get("approval") or {},
        mode=kwargs.get("mode") or "report-only",
        control_id="MDOHighConfidenceSpamAction",
        property_name="HighConfidenceSpamAction",
        desired_value="Quarantine",
    )

def _phishing_action(**kwargs):
    # Many tenants use PhishSpamAction on HostedContentFilterPolicy for phishing handling
    return _enforce_hcf_property(
        tenant=kwargs["tenant"],
        approval=kwargs.get("approval") or {},
        mode=kwargs.get("mode") or "report-only",
        control_id="MDOPhishingAction",
        property_name="PhishSpamAction",
        desired_value="Quarantine",
    )

register("MDOBulkSpamAction", _bulk_spam_action)
register("MDOHighConfidenceSpamAction", _high_conf_spam_action)
register("MDOPhishingAction", _phishing_action)
register("MDOBulkComplaintLevelThreshold", _bulk_complaint_level_threshold)
