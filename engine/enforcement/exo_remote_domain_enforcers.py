# engine/enforcement/exo_remote_domain_enforcers.py
from __future__ import annotations

import json
import subprocess
from typing import Any, Tuple

from engine.enforcement.registry import register


def _run_powershell(script: str, timeout: int = 240) -> Tuple[int, str, str]:
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
                timeout=timeout,
            )
            return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
        except FileNotFoundError:
            continue
    raise RuntimeError("Neither pwsh nor powershell is available on this system")


def _get_exo_cfg(tenant: dict) -> tuple[dict | None, dict | None]:
    exo = (tenant or {}).get("exoPowershell") or {}
    if not isinstance(exo, dict) or not exo:
        return None, {"reason": "Missing exoPowershell configuration in tenant JSON"}

    app_id = (exo.get("appId") or "").strip()
    thumb = (exo.get("certificateThumbprint") or "").strip()
    org = (exo.get("organization") or "").strip()

    # Allow delegated auth if app-only not present, but org must still exist
    if not org:
        return None, {"reason": "exoPowershell.organization is required"}

    return {"appId": app_id, "thumb": thumb, "org": org}, None


def _parse_json(s: str) -> dict:
    try:
        d = json.loads(s) if s else {}
        return d if isinstance(d, dict) else {"raw": s, "error": "Unexpected JSON (not an object)"}
    except Exception as e:
        return {"raw": s, "error": f"Failed to parse JSON: {e}"}


def _eval_autofwd_disabled(policies: list[dict]) -> tuple[bool, list[dict]]:
    # Conservative: missing/None counts as NOT disabled
    normalized = []
    ok = True
    for p in policies or []:
        ident = p.get("identity")
        val = p.get("AutoForwardEnabled")
        val_norm = True if str(val).strip().lower() in ("true", "1", "yes") else False if str(val).strip().lower() in ("false", "0", "no") else None
        normalized.append(
            {
                "identity": ident,
                "AutoForwardEnabled": val,
                "AutoForwardEnabled_normalized": val_norm,
                "AllowedOOFType": p.get("AllowedOOFType"),
                "TNEFEnabled": p.get("TNEFEnabled"),
            }
        )
        if val_norm is not False:
            ok = False
    return ok, normalized


def _enforce_mdo_block_auto_forwarding(**kwargs):
    """
    Control: MDOBlockAutoForwarding

    Enforces AutoForwardEnabled = $false on ALL Remote Domains via Exchange Online PowerShell.
    - report-only/detect-only: read + evaluate only
    - enforce: set + verify
    """
    tenant = kwargs["tenant"]
    mode = (kwargs.get("mode") or "report-only").strip().lower()

    cfg, err = _get_exo_cfg(tenant)
    if err:
        return ("ERROR", "MISSING_PREREQUISITE", err["reason"], {"error": err}, 400)

    app_id = cfg["appId"]
    thumb = cfg["thumb"]
    org = cfg["org"]

    # Build connect snippet (app-only if provided, otherwise delegated)
    if app_id and thumb:
        connect = f'Connect-ExchangeOnline -AppId "{app_id}" -CertificateThumbprint "{thumb}" -Organization "{org}" -ShowBanner:$false -ErrorAction Stop | Out-Null'
    else:
        connect = f'Connect-ExchangeOnline -Organization "{org}" -ShowBanner:$false -ErrorAction Stop | Out-Null'

    # 1) Always read current
    read_script = f"""
$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement
{connect}
try {{
  $items = Get-RemoteDomain -ErrorAction Stop
  $rows = @()
  foreach ($p in @($items)) {{
    $row = @{{
      identity = "$($p.Identity)"
      AutoForwardEnabled = $p.AutoForwardEnabled
      AllowedOOFType = $p.AllowedOOFType
      TNEFEnabled = $p.TNEFEnabled
    }}
    $rows += $row
  }}
  @{{
    ok = $true
    policiesCount = @($rows).Count
    policies = @($rows | Select-Object -First 50)
  }} | ConvertTo-Json -Depth 10
}} catch {{
  @{{
    ok = $false
    error = $_.Exception.Message
  }} | ConvertTo-Json -Depth 6
}} finally {{
  try {{ Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
}}
""".strip()

    rc, out, ps_err = _run_powershell(read_script, timeout=240)
    data = _parse_json(out)
    if rc != 0 or not data.get("ok"):
        return (
            "ERROR",
            "ENFORCER_ERROR",
            "Failed to read Remote Domains via EXO PowerShell",
            {"powershellExitCode": rc, "stderr": ps_err, "result": data},
            502,
        )

    policies = data.get("policies") or []
    ok, normalized = _eval_autofwd_disabled(policies)

    # report-only path
    if mode in ("report-only", "detect-only"):
        return (
            "COMPLIANT" if ok else "DRIFTED",
            "REPORT_ONLY_EVALUATED",
            "Report-only: evaluated Remote Domain auto-forwarding (no changes applied)",
            {"policies": normalized, "policiesCount": data.get("policiesCount")},
            200,
        )

    # enforce path: set + verify
    enforce_script = f"""
$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement
{connect}
try {{
  $items = Get-RemoteDomain -ErrorAction Stop
  $changed = @()
  foreach ($p in @($items)) {{
    if ($p.AutoForwardEnabled -ne $false) {{
      Set-RemoteDomain -Identity $p.Identity -AutoForwardEnabled:$false -ErrorAction Stop | Out-Null
      $changed += "$($p.Identity)"
    }}
  }}

  # verify
  $after = Get-RemoteDomain -ErrorAction Stop
  $rows = @()
  foreach ($p in @($after)) {{
    $rows += @{{
      identity = "$($p.Identity)"
      AutoForwardEnabled = $p.AutoForwardEnabled
      AllowedOOFType = $p.AllowedOOFType
      TNEFEnabled = $p.TNEFEnabled
    }}
  }}

  @{{
    ok = $true
    changed = $changed
    policiesCount = @($rows).Count
    policies = @($rows | Select-Object -First 50)
  }} | ConvertTo-Json -Depth 10
}} catch {{
  @{{
    ok = $false
    error = $_.Exception.Message
  }} | ConvertTo-Json -Depth 6
}} finally {{
  try {{ Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
}}
""".strip()

    rc2, out2, ps_err2 = _run_powershell(enforce_script, timeout=300)
    data2 = _parse_json(out2)
    if rc2 != 0 or not data2.get("ok"):
        return (
            "ERROR",
            "ENFORCER_ERROR",
            "Failed to enforce Remote Domain auto-forwarding via EXO PowerShell",
            {"powershellExitCode": rc2, "stderr": ps_err2, "result": data2},
            502,
        )

    policies2 = data2.get("policies") or []
    ok2, normalized2 = _eval_autofwd_disabled(policies2)
    if not ok2:
        return (
            "DRIFTED",
            "ENFORCER_EXECUTED",
            "Enforcer ran but verification still shows auto-forwarding enabled on one or more Remote Domains",
            {"changed": data2.get("changed"), "policies": normalized2, "policiesCount": data2.get("policiesCount")},
            207,
        )

    return (
        "COMPLIANT",
        "ENFORCER_EXECUTED",
        "Enforcer executed; auto-forwarding disabled on all Remote Domains",
        {"changed": data2.get("changed"), "policies": normalized2, "policiesCount": data2.get("policiesCount")},
        200,
    )


# Register
register("MDOBlockAutoForwarding", _enforce_mdo_block_auto_forwarding)
