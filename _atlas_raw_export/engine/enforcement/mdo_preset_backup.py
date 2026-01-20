# engine/enforcement/mdo_preset.py

import json
import subprocess
from typing import Any, Dict, Tuple
from engine.detectors import mdo as mdo_det


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
    # FAST PATH: avoid Connect-ExchangeOnline if we can evaluate via the cached EXO snapshot script.
    # This preserves conservative semantics and massively reduces runtime when EXO prewarm/snapshot is available.
    try:
        ok, snap = mdo_det._run_exo_ps("exo_preset_security_policies.ps1", tenant, timeout_s=60)
        if ok:
            eop_rules = mdo_det._as_list(snap.get("eopRules"))
            atp_rules = mdo_det._as_list(snap.get("atpRules"))

            def _state_for(name: str, rules: list[dict]) -> str | None:
                for r in rules:
                    if (r.get("Name") or "").strip().lower() == name.strip().lower():
                        return r.get("State")
                return None

            standard_name = STANDARD_NAME
            strict_name = STRICT_NAME

            eop_standard = _state_for(standard_name, eop_rules)
            eop_strict = _state_for(strict_name, eop_rules)
            atp_standard = _state_for(standard_name, atp_rules)
            atp_strict = _state_for(strict_name, atp_rules)

            # For "standard" baseline: strict also satisfies the requirement.
            if level.lower() == "strict":
                compliant = (eop_strict == "Enabled") and (atp_strict == "Enabled")
                winner = "strict" if compliant else None
            else:
                strict_ok = (eop_strict == "Enabled") and (atp_strict == "Enabled")
                standard_ok = (eop_standard == "Enabled") and (atp_standard == "Enabled")
                compliant = strict_ok or standard_ok
                winner = "strict" if strict_ok else ("standard" if standard_ok else None)

            fast_details: Dict[str, Any] = {
                "mode": mode,
                "level": level,
                "fastPath": True,
                "source": "exo_preset_security_policies.ps1",
                "eop": {"standard": eop_standard, "strict": eop_strict},
                "atp": {"standard": atp_standard, "strict": atp_strict},
                "winner": winner,
            }

            if mode == "report-only":
                return ("COMPLIANT" if compliant else "DRIFTED"), fast_details

            # enforce mode
            if compliant:
                return "COMPLIANT", fast_details
        else:
            # If snapshot path can't run (permissions/licensing/cmdlet missing), bubble it up clearly.
            msg = f"{(snap.get('stderr') or '')} {(snap.get('stdout') or '')} {(snap.get('reason') or '')}".lower()
            if ("not recognized" in msg) or ("is not recognized as the name of a cmdlet" in msg):
                return "NOT_EVALUATED", {
                    "mode": mode,
                    "level": level,
                    "fastPath": True,
                    "reasonCode": "LICENSING",
                    "reasonDetail": "EOP/ATP preset security policy cmdlets are unavailable in this tenant.",
                    "details": {"script": snap.get("script"), "exitCode": snap.get("exitCode")},
                }
            if ("access is denied" in msg) or ("unauthorized" in msg) or ("forbidden" in msg):
                return "NOT_EVALUATED", {
                    "mode": mode,
                    "level": level,
                    "fastPath": True,
                    "reasonCode": "PERMISSIONS",
                    "reasonDetail": "Insufficient permissions to read EOP/ATP preset security policy rules in EXO.",
                    "details": {"script": snap.get("script"), "exitCode": snap.get("exitCode")},
                }
    except Exception:
        # Fall through to legacy PS enforcement path (do not crash enforcement).
        pass

    # IMPORTANT: ps_script is defined unconditionally (fixes your UnboundLocalError)
    ps_script = """
$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -AppId "{app_id}" -CertificateThumbprint "{thumb}" -Organization "{org}" -ShowBanner:$false

function Get-PresetRules {
  $rules = @()
  $errs = @()

  try {
    $rules += Get-EOPProtectionPolicyRule | Select-Object Name,State
  } catch {
    $errs += ("EOP:" + $_.Exception.Message)
  }

  try {
    $rules += Get-ATPProtectionPolicyRule | Select-Object Name,State
  } catch {
    $errs += ("ATP:" + $_.Exception.Message)
  }

  # De-dupe by Name
  $dedup = @{}
  foreach ($r in $rules) {
    if ($r -and $r.Name) { $dedup[$r.Name] = $r }
  }

  return [PSCustomObject]@{
    rules = $dedup.Values
    errors = $errs
  }
}



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
$preset = $all | Where-Object {
  $_.Name -match "Preset" -and $_.Name -match "Security"
}}

$keyword = "{desired_keyword}"
$target = $preset | Where-Object {{ $_.Name.ToLower().Contains($keyword) }} | Select-Object -First 1

if (-not $target) {{
  $out = [PSCustomObject]@{
    mode = "{mode}"
    level = "{level}"
    keyword = $keyword
    error = "No matching preset security policy rule found"
    availableRules = ($preset | Select-Object Name,State)
    errors = $errors
  }

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
  $out = [PSCustomObject]@{
    mode = "{mode}"
    level = "{level}"
    keyword = $keyword
    error = "No matching preset security policy rule found"
    availableRules = ($preset | Select-Object Name,State)
    errors = $errors
  }

  $out | ConvertTo-Json -Compress
  Disconnect-ExchangeOnline -Confirm:$false
  exit
}}

if (-not $compliant) {{
  try {{ Enable-EOPProtectionPolicyRule -Identity $desiredName | Out-Null }} catch {{ $null = $null }}
  try {{ Enable-ATPProtectionPolicyRule -Identity $desiredName | Out-Null }} catch {{ $null = $null }}

  $after = Get-RuleState $desiredName
  $out = [PSCustomObject]@{
    mode = "{mode}"
    level = "{level}"
    keyword = $keyword
    error = "No matching preset security policy rule found"
    availableRules = ($preset | Select-Object Name,State)
    errors = $errors
  }

  $out | ConvertTo-Json -Compress
}} else {{
  $out = [PSCustomObject]@{
    mode = "{mode}"
    level = "{level}"
    keyword = $keyword
    error = "No matching preset security policy rule found"
    availableRules = ($preset | Select-Object Name,State)
    errors = $errors
  }

  $out | ConvertTo-Json -Compress
}}

Disconnect-ExchangeOnline -Confirm:$false
"""

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
