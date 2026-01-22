# engine/enforcement/mdo_preset.py

import json
import subprocess
from typing import Any, Dict, Tuple
from engine.detectors import mdo as mdo_det
from engine.enforcement.registry import register
from engine.approvals.reader import is_control_approved


STANDARD_NAME = "Standard Preset Security Policy"
STRICT_NAME = "Strict Preset Security Policy"


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
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except FileNotFoundError:
            continue

    raise RuntimeError("Neither pwsh nor powershell is available on this system")


def apply_mdo_preset_security_policies(
    tenant: dict,
    mode: str = "report-only",
    level: str = "standard",
) -> Tuple[str, Dict[str, Any]]:
    """
    Enforce or report-only check for MDO Preset Security Policies.

    mode:
      - report-only  (no changes)
      - enforce      (enable policy)

    level:
      - standard
      - strict
    """

    mode = (mode or "report-only").strip().lower()
    level = (level or "standard").strip().lower()
    desired_keyword = "standard" if level == "standard" else "strict"

    exo = tenant.get("exoPowershell") or {}
    if not exo:
        return "ERROR", {"reason": "Missing exoPowershell configuration in tenant JSON"}

    app_id = exo.get("appId")
    thumb = exo.get("certificateThumbprint")
    org = exo.get("organization")

    if not (app_id and thumb and org):
        return "ERROR", {
            "reason": "exoPowershell config incomplete",
            "expected": ["appId", "certificateThumbprint", "organization"],
        }
    # FAST PATH (snapshots): if the engine is invoking this enforcer in a NOT_EVALUATED execution path
    # (action=ensure_not_evaluated), we must not pay for Connect-ExchangeOnline.
    # We try a cheap snapshot-backed read for evidence and always exit quickly in enforce mode.
    if mode != "report-only":
        try:
            ok, snap = mdo_det._run_exo_ps("exo_preset_security_policies.ps1", tenant, timeout_s=3)
            if ok:
                eop_rules = mdo_det._as_list(snap.get("eopRules"))
                atp_rules = mdo_det._as_list(snap.get("atpRules"))
                if not eop_rules and not atp_rules:
                    return "NOT_EVALUATED", {
                        "mode": mode,
                        "level": level,
                        "fastPath": True,
                        "source": "exo_preset_security_policies.ps1",
                        "reasonCode": "LICENSING",
                        "reasonDetail": "No preset security policy rules are exposed in this tenant (likely licensing / feature unavailable).",
                        "details": {"eopRulesCount": 0, "atpRulesCount": 0},
                    }
        except Exception:
            pass

        # Always skip Connect-ExchangeOnline for ensure_not_evaluated runs.
        return "NOT_EVALUATED", {
            "mode": mode,
            "level": level,
            "fastPath": True,
            "reasonCode": "BLOCKED",
            "reasonDetail": "Skipped enforcement because control action is ensure_not_evaluated.",
            "details": {"skipped": True},
        }

    # IMPORTANT: ps_script is defined unconditionally (fixes your UnboundLocalError)
    ps_script = """
$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -AppId "{app_id}" -CertificateThumbprint "{thumb}" -Organization "{org}" -ShowBanner:$false

function Get-PresetRules {{
  $rules = @()
  $errs = @()

  try {{
    $rules += Get-EOPProtectionPolicyRule | Select-Object Name,State
  }} catch {{
    $errs += ("EOP:" + $_.Exception.Message)
  }}

  try {{
    $rules += Get-ATPProtectionPolicyRule | Select-Object Name,State
  }} catch {{
    $errs += ("ATP:" + $_.Exception.Message)
  }}

  # De-dupe by Name
  $dedup = @{{}}
  foreach ($r in $rules) {{
    if ($r -and $r.Name) {{ $dedup[$r.Name] = $r }}
  }}

  return [PSCustomObject]@{{
    rules = $dedup.Values
    errors = $errs
  }}
}}

function Get-RuleState($name) {{
  $eop = $null
  $atp = $null

  try {{
    $eop = Get-EOPProtectionPolicyRule -Identity $name | Select-Object -First 1 Name,State
  }} catch {{
    $null = $null
  }}

  try {{
    $atp = Get-ATPProtectionPolicyRule -Identity $name | Select-Object -First 1 Name,State
  }} catch {{
    $null = $null
  }}

  [PSCustomObject]@{{
    name = $name
    eopState = if ($eop) {{ $eop.State.ToString() }} else {{ $null }}
    atpState = if ($atp) {{ $atp.State.ToString() }} else {{ $null }}
  }}
}}

$allObj = Get-PresetRules
$all = $allObj.rules
$errors = $allObj.errors

# Rules that look like preset security policies
$preset = $all | Where-Object {{
  $_.Name -match "Preset" -and $_.Name -match "Security"
}}

$keyword = "{desired_keyword}"
$target = $preset | Where-Object {{ $_.Name.ToLower().Contains($keyword) }} | Select-Object -First 1

if (-not $target) {{
  $out = [PSCustomObject]@{{
    mode = "{mode}"
    level = "{level}"
    keyword = $keyword
    error = "No matching preset security policy rule found"
    availableRules = ($preset | Select-Object Name,State)
    errors = $errors
  }}

  $out | ConvertTo-Json -Compress
  Disconnect-ExchangeOnline -Confirm:$false
  exit
}}

$desiredName = $target.Name
$state = Get-RuleState $desiredName

$eopEnabled = ($state.eopState -eq "Enabled")
$atpEnabled = ($state.atpState -eq "Enabled")
$compliant = $eopEnabled -and $atpEnabled

if ("{mode}" -eq "report-only") {{
  $out = [PSCustomObject]@{{
    mode = "{mode}"
    level = "{level}"
    keyword = $keyword
    compliant = $compliant
    desiredName = $desiredName
    state = $state
    availableRules = ($preset | Select-Object Name,State)
    errors = $errors
  }}

  $out | ConvertTo-Json -Compress
  Disconnect-ExchangeOnline -Confirm:$false
  exit
}}

if (-not $compliant) {{
  try {{ Enable-EOPProtectionPolicyRule -Identity $desiredName | Out-Null }} catch {{ $null = $null }}
  try {{ Enable-ATPProtectionPolicyRule -Identity $desiredName | Out-Null }} catch {{ $null = $null }}

  $after = Get-RuleState $desiredName
  $out = [PSCustomObject]@{{
    mode = "{mode}"
    level = "{level}"
    keyword = $keyword
    action = "enabled_attempted"
    compliant = (($after.eopState -eq "Enabled") -and ($after.atpState -eq "Enabled"))
    desiredName = $desiredName
    before = $state
    after = $after
    availableRules = ($preset | Select-Object Name,State)
    errors = $errors
  }}

  $out | ConvertTo-Json -Compress
}} else {{
  $out = [PSCustomObject]@{{
    mode = "{mode}"
    level = "{level}"
    keyword = $keyword
    compliant = $true
    desiredName = $desiredName
    state = $state
    availableRules = ($preset | Select-Object Name,State)
    errors = $errors
  }}

  $out | ConvertTo-Json -Compress
}}

Disconnect-ExchangeOnline -Confirm:$false
""".format(
    app_id=app_id,
    thumb=thumb,
    org=org,
    desired_keyword=desired_keyword,
    mode=mode,
    level=level,
)


    code, stdout, stderr = _run_powershell(ps_script)

    if code != 0:
        return "ERROR", {"stderr": stderr, "stdout": stdout}

    try:
        result = json.loads(stdout) if stdout else {}
    except Exception:
        return "ERROR", {
            "reason": "Failed to parse PowerShell output (expected JSON)",
            "raw_stdout": stdout,
            "raw_stderr": stderr,
        }

    # If PowerShell couldn't find any matching rules, it exits after writing JSON.
    if result.get("error"):
        # No preset rules exist in this tenant -> not enforceable / not applicable
        return "NOT_EVALUATED", result


    if mode == "report-only":
        return ("COMPLIANT" if result.get("compliant") else "DRIFTED"), result

    if result.get("action") == "enabled_attempted":
        # Could still be drifted if enable didn't actually stick, but this signals we attempted change.
        return "UPDATED", result

    return "COMPLIANT", result
CONTROL_ID = "MDOPresetSecurityPolicies"

@register(CONTROL_ID)
def enforce_mdo_preset_security_policies(ctx: dict, tenant_name: str, approvals_cache: dict):
    approval = is_control_approved(tenant_name, CONTROL_ID, approvals_cache) or {}
    mode = (approval.get("mode") or "report-only").lower()

    # Hard gate: never enforce without explicit approval + enforce mode
    if not approval.get("approved") or mode != "enforce":
        return (
            "NOT_EVALUATED",
            "APPROVAL_REQUIRED",
            f"{CONTROL_ID} requires an approval file with approved=true and mode=enforce.",
            {"approved": bool(approval.get("approved")), "mode": mode},
            0,
        )

    # Optional: allow approval JSON to specify preset name (defaults inside your existing code)
    preset_name = approval.get("preset") or approval.get("presetName") or "Standard"

    try:
        # This should call your existing implementation (adjust the function name if yours differs)
        result = apply_mdo_preset(ctx, preset_name=preset_name)

        # Expecting result like {"state": "...", "details": {...}} or similar
        if isinstance(result, dict):
            state = result.get("state") or "NOT_EVALUATED"
            details = result.get("details") or {}
            return (state, "", "", details, 0)

        # Fallback if your function returns a tuple
        if isinstance(result, tuple) and len(result) == 2:
            return (result[0], "", "", result[1] or {}, 0)

        return ("NOT_EVALUATED", "UNEXPECTED_RETURN", "mdo_preset returned an unexpected type.", {"raw": str(result)}, 0)

    except Exception as e:
        return ("NOT_EVALUATED", "ERROR", f"Failed to enforce {CONTROL_ID}: {e}", {"exception": str(e)}, 0)
