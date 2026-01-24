from __future__ import annotations

import json
import subprocess
from typing import Any, Tuple

from engine.enforcement.registry import register


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
    raise RuntimeError("Neither pwsh nor powershell is available")


def _get_exo_cfg(tenant: dict) -> tuple[str, str, str] | None:
    exo = (tenant or {}).get("exoPowershell") or {}
    app_id = exo.get("appId")
    thumb = exo.get("certificateThumbprint")
    org = exo.get("organization")
    if not (app_id and thumb and org):
        return None
    return app_id, thumb, org


def _mdo_safe_links_office_apps(**kwargs):
    tenant = kwargs["tenant"]
    approval = kwargs.get("approval") or {}
    mode = (kwargs.get("mode") or "report-only").strip().lower()

    if mode == "enforce" and approval.get("approved") is not True:
        return ("NOT_EVALUATED", "APPROVAL_REQUIRED", "Approval required for enforce mode", {}, 409)

    exo_cfg = _get_exo_cfg(tenant)
    if not exo_cfg:
        return ("ERROR", "MISSING_PREREQUISITE", "Missing/incomplete exoPowershell config", {}, 424)

    app_id, thumb, org = exo_cfg

    # Baseline
    desired_enable_office = True
    desired_track_clicks = True
    desired_allow_clickthrough = False

    ps = fr"""
$ErrorActionPreference = "Stop"
$WarningPreference = "SilentlyContinue"

Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -AppId "{app_id}" -CertificateThumbprint "{thumb}" -Organization "{org}" -ShowBanner:$false | Out-Null

$Mode = "{mode}"

function Snapshot() {{
  $pol = @(
    Get-SafeLinksPolicy -ErrorAction Stop |
      Select-Object Name,IsDefault,Identity,EnableSafeLinksForOffice,TrackClicks,AllowClickThrough
  )
  $rules = @(
    Get-SafeLinksRule -ErrorAction Stop |
      Select-Object Name,State,SafeLinksPolicy,Priority,Identity
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

  # Deterministic target:
  # 1) Prefer existing "ATLAS Safe Links Policy" if present
  # 2) Else if exactly one non-default exists, use it
  # 3) Else if only default exists:
  #    - report-only: return drift/not evaluated without guessing
  #    - enforce: create ATLAS policy + baseline rule
  $atlasPolicyName = "ATLAS Safe Links Policy"
  $target = $before.policies | Where-Object {{ $_.Name -eq $atlasPolicyName }} | Select-Object -First 1

  if (-not $target) {{
    $custom = @($before.policies | Where-Object {{ $_.IsDefault -eq $false }})
    if ($custom.Count -eq 1) {{
      $target = $custom[0]
    }} elseif ($custom.Count -gt 1) {{
      $out = [PSCustomObject]@{{
        mode         = $Mode
        action       = "blocked_multiple_custom_policies"
        compliant    = $false
        reasonCode   = "UNSUPPORTED_MODE"
        reasonDetail = "Multiple non-default Safe Links policies exist; cannot deterministically choose one."
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
          reasonCode = "MISSING_SIGNAL"
          reasonDetail = "No non-default Safe Links policy found; enforce would require creating ATLAS policy."
          before    = $before
        }}
        $out | ConvertTo-Json -Depth 10
        exit 0
      }}

      New-SafeLinksPolicy -Name $atlasPolicyName -ErrorAction Stop | Out-Null
      $target = Get-SafeLinksPolicy | Where-Object {{ $_.Name -eq $atlasPolicyName }} | Select-Object -First 1

      # Ensure baseline rule so policy applies broadly
      $ruleName = "ATLAS Baseline Safe Links"
      $existingRule = Get-SafeLinksRule | Where-Object {{ $_.Name -eq $ruleName }} | Select-Object -First 1
      if (-not $existingRule -and $target -and $target.Identity) {{
        New-SafeLinksRule -Name $ruleName -SafeLinksPolicy $target.Identity -RecipientDomainIs @("*") -Priority 0 -ErrorAction Stop | Out-Null
      }}
    }}
  }}

  if (-not $target -or -not $target.Identity) {{
    $out = [PSCustomObject]@{{
      mode         = $Mode
      action       = "blocked_no_target_policy"
      compliant    = $false
      reasonCode   = "MISSING_SIGNAL"
      reasonDetail = "No usable Safe Links policy identity found."
      before       = $before
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }}

  $desiredEnableOffice = $true
  $desiredTrackClicks = $true
  $desiredAllowClick = $false

  $current = ($before.policies | Where-Object {{ $_.Identity -eq $target.Identity }} | Select-Object -First 1)

  $needsChange = $false
  if ($current.EnableSafeLinksForOffice -ne $desiredEnableOffice) {{ $needsChange = $true }}
  if ($current.TrackClicks -ne $desiredTrackClicks) {{ $needsChange = $true }}
  if ($current.AllowClickThrough -ne $desiredAllowClick) {{ $needsChange = $true }}

  if (-not $needsChange) {{
    $out = [PSCustomObject]@{{
      mode      = $Mode
      action    = "no_change"
      compliant = $true
      target    = $target.Name
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
      current   = $current
      desired   = [PSCustomObject]@{{
        EnableSafeLinksForOffice = $desiredEnableOffice
        TrackClicks              = $desiredTrackClicks
        AllowClickThrough        = $desiredAllowClick
      }}
      before    = $before
    }}
    $out | ConvertTo-Json -Depth 10
    exit 0
  }}

  Set-SafeLinksPolicy -Identity $target.Identity `
    -EnableSafeLinksForOffice $desiredEnableOffice `
    -TrackClicks $desiredTrackClicks `
    -AllowClickThrough $desiredAllowClick `
    -ErrorAction Stop | Out-Null

  $after = Snapshot
  $afterRow = ($after.policies | Where-Object {{ $_.Identity -eq $target.Identity }} | Select-Object -First 1)

  $compliant = ($afterRow.EnableSafeLinksForOffice -eq $desiredEnableOffice) -and `
               ($afterRow.TrackClicks -eq $desiredTrackClicks) -and `
               ($afterRow.AllowClickThrough -eq $desiredAllowClick)

  $out = [PSCustomObject]@{{
    mode      = $Mode
    action    = "set_policy_properties"
    compliant = $compliant
    target    = $target.Name
    beforeVal = $current
    afterVal  = $afterRow
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


register("MDOSafeLinksOfficeApps", _mdo_safe_links_office_apps)
