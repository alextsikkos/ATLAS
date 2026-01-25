# engine/enforcement/mdo_hosted_content_filter_bulk.py
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, Tuple


# Map controlId -> (propertyName, desiredValue)
CONTROL_FIELD_MAP: Dict[str, Tuple[str, Any]] = {
    "MDOBulkSpamAction": ("BulkSpamAction", "Quarantine"),
    "MDOHighConfidenceSpamAction": ("HighConfidenceSpamAction", "Quarantine"),
    "MDOPhishingAction": ("PhishSpamAction", "Quarantine"),
    "MDOQuarantineRetentionPeriod": ("QuarantineRetentionPeriod", 30),
    "MDOBlockAutoForwarding": ("AutoForwardingMode", "Off"),
    "MDOAntiSpam": ("BulkSpamAction", "Quarantine"),  # if your AntiSpam control is driven by hosted content filter settings
    "MDOBulkComplaintLevelThreshold": ("BulkComplaintLevelThreshold", 6),

    # Add these later when you implement them:
    # "MDOBulkComplaintLevelThreshold": ("BulkComplaintLevelThreshold", 6),
    # "MDOThresholdReachedAction": ("ThresholdReachedAction", "Quarantine"),
    # "MDOSpamNotificationsAdminsOnly": ("SpamNotificationsEnabled", False),  # example; confirm actual EXO property
}


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


def _read_approval(tenant_name: str, control_id: str) -> dict:
    """
    Bulk runner must be file-based approvals only.
    approvals/<tenant>/<control_id>.json
    """
    path = os.path.join("approvals", tenant_name, f"{control_id}.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _run_bulk_once(tenant: dict, tenant_name: str, ctx: dict) -> dict:
    """
    Bulk-executes all matched HostedContentFilter controls in ONE EXO session.
    Returns ctx with ctx["results"][controlId] populated in the same shape as other bulk modules.
    """
    matched = tenant.get("_atlas_matched_controls") or []
    matched_ids = [c.get("atlasControlId") for c in matched if isinstance(c, dict)]
    target_ids = [cid for cid in matched_ids if cid in CONTROL_FIELD_MAP]

    if not target_ids:
        return ctx

    modes = {}
    approvals = {}


    exo_cfg = _get_exo_config(tenant)
    if not exo_cfg:
        # mark all as missing prerequisite
        results = {}
        for cid in target_ids:
            results[cid] = ("ERROR", "MISSING_PREREQUISITE", "Missing/incomplete exoPowershell config", {}, 424)
        ctx["results"] = {**(ctx.get("results") or {}), **results}
        return ctx

    app_id, thumb, org = exo_cfg

    # Build per-control approval+mode
    control_specs = []
    for cid in target_ids:
        approval = _read_approval(tenant_name, cid)
        mode = (approval.get("mode") or "report-only").strip().lower()
        approved = approval.get("approved") is True
        effective_mode = "enforce" if (approved and mode == "enforce") else "report-only"
        modes[cid] = effective_mode
        approvals[cid] = (effective_mode == "enforce")

        prop, desired = CONTROL_FIELD_MAP[cid]
        control_specs.append(
            {
                "controlId": cid,
                "mode": mode,
                "approved": approved,
                "property": prop,
                "desired": desired,
            }
        )

    specs_json = json.dumps(control_specs).replace('"', '\\"')

    ps = fr"""
$ErrorActionPreference = "Stop"
$WarningPreference = "SilentlyContinue"

Import-Module ExchangeOnlineManagement

function Snapshot() {{
  $pol = @(
    Get-HostedContentFilterPolicy -ErrorAction Stop |
      Select-Object Name,IsDefault,Identity,BulkSpamAction,HighConfidenceSpamAction,PhishSpamAction,QuarantineRetentionPeriod
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
  Connect-ExchangeOnline -AppId "{app_id}" -CertificateThumbprint "{thumb}" -Organization "{org}" -ShowBanner:$false | Out-Null

  $Specs = "{specs_json}" | ConvertFrom-Json

  $before = Snapshot

  # Determine target policy (same deterministic rules as your single enforcers)
  $custom = @($before.policies | Where-Object {{ $_.IsDefault -eq $false }})
  $target = $null

  if ($custom.Count -eq 1) {{
    $target = $custom[0]
  }} elseif ($custom.Count -gt 1) {{
    $results = @{{}}
    foreach ($s in $Specs) {{
      $results[$s.controlId] = [PSCustomObject]@{{
        mode         = $s.mode
        action       = "blocked_multiple_custom_policies"
        compliant    = $false
        reasonCode   = "UNSUPPORTED_MODE"
        reasonDetail = "Multiple non-default HostedContentFilter policies exist; cannot deterministically choose one."
        before       = $before
      }}
    }}
    @{{
      results = $results
    }} | ConvertTo-Json -Depth 10
    return
  }} else {{
    # no custom policies
    $anyEnforceApproved = $false
    foreach ($s in $Specs) {{
      if ($s.mode -eq "enforce" -and $s.approved -eq $true) {{ $anyEnforceApproved = $true }}
    }}

    if (-not $anyEnforceApproved) {{
      $results = @{{}}
      foreach ($s in $Specs) {{
        $results[$s.controlId] = [PSCustomObject]@{{
          mode      = $s.mode
          action    = "report_only_no_custom_policy"
          compliant = $false
          before    = $before
        }}
      }}
      @{{
        results = $results
      }} | ConvertTo-Json -Depth 10
      return
    }}

    $atlasPolicyName = "ATLAS AntiSpam Policy"
    New-HostedContentFilterPolicy -Name $atlasPolicyName -ErrorAction Stop | Out-Null

    $target = Get-HostedContentFilterPolicy | Where-Object {{ $_.Name -eq $atlasPolicyName }} | Select-Object -First 1

    # Ensure baseline rule exists
    $ruleName = "ATLAS Baseline AntiSpam"
    $existingRule = Get-HostedContentFilterRule | Where-Object {{ $_.Name -eq $ruleName }} | Select-Object -First 1
    if (-not $existingRule -and $target -and $target.Identity) {{
      New-HostedContentFilterRule -Name $ruleName -HostedContentFilterPolicy $target.Identity -RecipientDomainIs @("*") -Priority 0 -ErrorAction Stop | Out-Null
    }}
  }}

  if (-not $target -or -not $target.Identity) {{
    $results = @{{}}
    foreach ($s in $Specs) {{
      $results[$s.controlId] = [PSCustomObject]@{{
        mode         = $s.mode
        action       = "blocked_no_target_policy"
        compliant    = $false
        reasonCode   = "MISSING_SIGNAL"
        reasonDetail = "No usable HostedContentFilter policy identity found."
        before       = $before
      }}
    }}
    @{{
      results = $results
    }} | ConvertTo-Json -Depth 10
    return
  }}

  # Build desired set for enforce+approved controls that are drifted
  $targetRow = ($before.policies | Where-Object {{ $_.Identity -eq $target.Identity }} | Select-Object -First 1)

  $setParams = @{{ Identity = $target.Identity }}
  $results = @{{}}

  foreach ($s in $Specs) {{
    $prop = $s.property
    $desired = $s.desired
    $current = $null
    try {{ $current = $targetRow.$prop }} catch {{}}

    if ($current -eq $desired) {{
      $results[$s.controlId] = [PSCustomObject]@{{
        mode      = $s.mode
        action    = "no_change"
        compliant = $true
        target    = $target.Name
        property  = $prop
        value     = $current
        before    = $before
      }}
      continue
    }}

    if ($s.mode -ne "enforce") {{
      $results[$s.controlId] = [PSCustomObject]@{{
        mode      = $s.mode
        action    = "report_only_drift"
        compliant = $false
        target    = $target.Name
        property  = $prop
        current   = $current
        desired   = $desired
        before    = $before
      }}
      continue
    }}

    if ($s.approved -ne $true) {{
      $results[$s.controlId] = [PSCustomObject]@{{
        mode         = $s.mode
        action       = "blocked_not_approved"
        compliant    = $false
        reasonCode   = "APPROVAL_REQUIRED"
        reasonDetail = "Approval required for enforce mode."
        target       = $target.Name
        property     = $prop
        current      = $current
        desired      = $desired
        before       = $before
      }}
      continue
    }}

    # enforce later in one Set-HostedContentFilterPolicy call
    $setParams[$prop] = $desired
    $results[$s.controlId] = [PSCustomObject]@{{
      mode      = $s.mode
      action    = "will_set"
      compliant = $false
      target    = $target.Name
      property  = $prop
      beforeVal = $current
      desired   = $desired
      before    = $before
    }}
  }}

  $didSet = $false
  if ($setParams.Keys.Count -gt 1) {{
    Set-HostedContentFilterPolicy @setParams -ErrorAction Stop | Out-Null
    $didSet = $true
  }}

  $after = Snapshot
  $afterRow = ($after.policies | Where-Object {{ $_.Identity -eq $target.Identity }} | Select-Object -First 1)

  foreach ($cid in $results.Keys) {{
    $r = $results[$cid]
    if ($r.action -ne "will_set") {{ continue }}

    $prop = $r.property
    $desired = $r.desired
    $afterVal = $null
    try {{ $afterVal = $afterRow.$prop }} catch {{}}

    $results[$cid] = [PSCustomObject]@{{
      mode      = "enforce"
      action    = "set_policy_property"
      compliant = ($afterVal -eq $desired)
      target    = $target.Name
      property  = $prop
      beforeVal = $r.beforeVal
      afterVal  = $afterVal
      desired   = $desired
      before    = $before
      after     = $after
    }}
  }}

  @{{
    results = $results
  }} | ConvertTo-Json -Depth 10
}}
finally {{
  try {{ Disconnect-ExchangeOnline -Confirm:$false | Out-Null }} catch {{}}
}}
"""

    code, stdout, stderr = _run_powershell(ps)
    if code != 0:
        # mark all as error
        results = {}
        for cid in target_ids:
            results[cid] = ("ERROR", "ENFORCER_ERROR", "PowerShell failed", {"stderr": stderr, "stdout": stdout}, 500)
        ctx["results"] = {**(ctx.get("results") or {}), **results}
        return ctx

    try:
        payload = json.loads(stdout) if stdout else {}
    except Exception:
        results = {}
        for cid in target_ids:
            results[cid] = ("ERROR", "ENFORCER_ERROR", "Failed to parse PowerShell JSON", {"raw_stdout": stdout, "raw_stderr": stderr}, 500)
        ctx["results"] = {**(ctx.get("results") or {}), **results}
        return ctx

    results_out = {}
    ps_results = payload.get("results") or {}
    for cid, r in ps_results.items():
        action = r.get("action")
        compliant = bool(r.get("compliant"))
        # Map to ATLAS-style tuple
        if action and str(action).startswith("blocked_"):
            results_out[cid] = (
                "NOT_EVALUATED",
                r.get("reasonCode") or "UNSUPPORTED_MODE",
                r.get("reasonDetail") or "Blocked by safety rules",
                r,
                200,
            )
        else:
            results_out[cid] = (
                "COMPLIANT" if compliant else "DRIFTED",
                "ENFORCER_EXECUTED",
                "Hosted content filter bulk evaluated/enforced",
                r,
                200,
            )

    ctx["results"] = {**(ctx.get("results") or {}), **results_out}
    return ctx
