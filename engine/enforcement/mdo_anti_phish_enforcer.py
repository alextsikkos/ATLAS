# engine/enforcement/mdo_anti_phish_enforcer.py
from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, Tuple

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


def _enforce_mdo_anti_phish(**kwargs) -> tuple[str, str, str, dict, int]:
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

    # Approval gate for enforce mode (report-only can still evaluate)
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
    Import-Module ExchangeOnlineManagement

    $AppId = "{app_id}"
    $Thumb = "{thumb}"
    $Org = "{org}"
    $Mode = "{mode}"

    Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $Thumb -Organization $Org -ShowBanner:$false | Out-Null

    function Snapshot() {{
    $pol = @(Get-AntiPhishPolicy -ErrorAction Stop | Select-Object Name,Enabled,IsBuiltInProtection,IsValid,Identity)
    $rules = @(Get-AntiPhishRule -ErrorAction Stop | Select-Object Name,State,AntiPhishPolicy,Priority,Identity)
    return [PSCustomObject]@{{
        policyCount = $pol.Count
        ruleCount = $rules.Count
        policies = $pol
        rules = $rules
    }}
    }}

    try {{
    $before = Snapshot
    $enabled = @($before.rules | Where-Object {{ $_.State -eq "Enabled" }})

    if ($enabled.Count -ge 1) {{
        $out = [PSCustomObject]@{{
        mode = $Mode
        compliant = $true
        action = "no_change"
        before = $before
        }}
        $out | ConvertTo-Json -Depth 10
        exit 0
    }}

    if ($Mode -ne "enforce") {{
        $out = [PSCustomObject]@{{
        mode = $Mode
        compliant = $false
        action = "report_only_drift"
        before = $before
        }}
        $out | ConvertTo-Json -Depth 10
        exit 0
    }}

    if ($before.ruleCount -eq 0) {{
        $baselineRuleName = "ATLAS Baseline AntiPhish"
        # Determine target policy (never use built-in)
        $targetPolicy = $null

        $custom = @($before.policies | Where-Object {{ $_.IsBuiltInProtection -ne $true }} | Select-Object -First 1)
        if ($custom.Count -ge 1) {{
            $targetPolicy = $custom[0]
        }} else {{
            $atlasPolicyName = "ATLAS AntiPhish Policy"
            try {{
                New-AntiPhishPolicy -Name $atlasPolicyName -Enabled $true -ErrorAction Stop | Out-Null
            }} catch {{}}
            $targetPolicy = Get-AntiPhishPolicy | Where-Object {{ $_.Name -eq $atlasPolicyName }} | Select-Object -First 1
        }}
        if (-not $targetPolicy -or -not $targetPolicy.Identity) {{
            $out = [PSCustomObject]@{{
                mode = $Mode
                compliant = $false
                action = "blocked_no_rules"
                reasonCode = "MISSING_SIGNAL"
                reasonDetail = "No usable AntiPhish policy identity available for baseline enforcement."
                before = $before
            }}
            $out | ConvertTo-Json -Depth 10
            exit 0
        }}

        New-AntiPhishRule -Name $baselineRuleName -AntiPhishPolicy $targetPolicy.Identity -RecipientDomainIs @("*") -Priority 0 -ErrorAction Stop | Out-Null

        try {{
        Set-AntiPhishPolicy -Identity $targetPolicy.Identity -Enabled $true -ErrorAction Stop | Out-Null
        }} catch {{}}

        $after = Snapshot
        $enabledAfter = @($after.rules | Where-Object {{ $_.State -eq "Enabled" }})

        $out = [PSCustomObject]@{{
        mode = $Mode
        action = "created_baseline_rule"
        compliant = ($enabledAfter.Count -ge 1)
        createdRuleName = $baselineRuleName
        targetPolicy = $targetPolicy.Name
        before = $before
        after = $after
        }}
        $out | ConvertTo-Json -Depth 10
        exit 0
    }}

    if ($before.ruleCount -gt 1) {{
        $out = [PSCustomObject]@{{
        mode = $Mode
        compliant = $false
        action = "blocked_multiple_rules"
        reasonCode = "UNSUPPORTED_MODE"
        reasonDetail = "Multiple AntiPhish rules exist and none are enabled; manual selection required."
        before = $before
        }}
        $out | ConvertTo-Json -Depth 10
        exit 0
    }}

    $r = $before.rules | Select-Object -First 1
    try {{
        Set-AntiPhishRule -Identity $r.Identity -State Enabled -ErrorAction Stop | Out-Null
    }} catch {{
        try {{
        Set-AntiPhishRule -Identity $r.Name -State Enabled -ErrorAction Stop | Out-Null
        }} catch {{
        throw
        }}
    }}

    $policyName = $r.AntiPhishPolicy
    if ($policyName) {
        try {
            $polObj = Get-AntiPhishPolicy | Where-Object { $_.Name -eq $policyName } | Select-Object -First 1
            if ($polObj -and $polObj.Identity) {
                Set-AntiPhishPolicy -Identity $polObj.Identity -Enabled $true -ErrorAction Stop | Out-Null
            }
        } catch {}
    }



    $after = Snapshot
    $enabledAfter = @($after.rules | Where-Object {{ $_.State -eq "Enabled" }})

    $out = [PSCustomObject]@{{
        mode = $Mode
        action = "enabled_single_rule"
        compliant = ($enabledAfter.Count -ge 1)
        before = $before
        after = $after
    }}
    $out | ConvertTo-Json -Depth 10
    }} finally {{
    try {{ Disconnect-ExchangeOnline -Confirm:$false | Out-Null }} catch {{}}
    }}
    """


    code, stdout, stderr = _run_powershell(ps)

    if code != 0:
        return (
            "ERROR",
            "ENFORCER_ERROR",
            "PowerShell execution failed for MDOAntiPhish",
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

    # blocked cases (explicit)
    if action in ("blocked_multiple_rules", "blocked_no_rules"):
        return (
            "NOT_EVALUATED",
            result.get("reasonCode") or "UNSUPPORTED_MODE",
            result.get("reasonDetail") or "Enforcement blocked by safety rules",
            {"result": result},
            409,
        )

    # report-only evaluation
    if mode != "enforce":
        if compliant:
            return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: anti-phish rules enabled", {"result": result}, 200)
        return ("DRIFTED", "REPORT_ONLY_EVALUATED", "Report-only: no enabled anti-phish rules found", {"result": result}, 200)

    # enforce evaluation
    if compliant:
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforcer executed; anti-phish rule enabled/verified", {"result": result}, 200)

    return ("DRIFTED", "ENFORCER_EXECUTED", "Enforcer executed but verification did not show enabled rule", {"result": result}, 200)


# Register
register("MDOAntiPhish", _enforce_mdo_anti_phish)
