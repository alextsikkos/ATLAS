import json
import os
import subprocess
from typing import Any, Dict, Tuple

# ControlId -> (PolicyPropertyName, DesiredValue)
CONTROL_FIELD_MAP = {
    "MDOSafeLinks": ("EnableSafeLinksForEmail", True),
    "MDOSafeLinksOfficeApps": ("EnableSafeLinksForOffice", True),
}



def _run_powershell(script: str) -> Tuple[int, str, str]:
    p = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
    )
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def _get_exo_config(tenant: dict):
    exo = (tenant or {}).get("exoPowershell") or {}
    app_id = exo.get("appId")
    thumb = exo.get("certificateThumbprint")
    org = exo.get("organization")
    if not (app_id and thumb and org):
        return None
    return app_id, thumb, org

def _read_approval(tenant_name: str, control_id: str) -> dict:
    path = os.path.join("approvals", tenant_name, f"{control_id}.json")
    if not os.path.exists(path):
        return {}
    try:
        return json.loads(open(path, "r", encoding="utf-8").read())
    except Exception:
        return {}

def _run_bulk_once(tenant: dict, tenant_name: str, ctx: dict) -> dict:
    matched = tenant.get("_atlas_matched_controls") or []
    matched_ids = [c.get("atlasControlId") for c in matched if isinstance(c, dict)]
    target_ids = [cid for cid in matched_ids if cid in CONTROL_FIELD_MAP]
    if not target_ids:
        return ctx

    results: Dict[str, Any] = {}
    exo_cfg = _get_exo_config(tenant)
    if not exo_cfg:
        for cid in target_ids:
            results[cid] = ("ERROR", "MISSING_PREREQUISITE", "Missing/incomplete exoPowershell config", {}, 424)
        ctx["results"] = {**(ctx.get("results") or {}), **results}
        return ctx

    app_id, thumb, org = exo_cfg

    control_specs = []
    for cid in target_ids:
        approval = _read_approval(tenant_name, cid)
        mode = (approval.get("mode") or "report-only").strip().lower()
        approved = approval.get("approved") is True
        effective_mode = "enforce" if (approved and mode == "enforce") else "report-only"
        prop, desired = CONTROL_FIELD_MAP[cid]
        control_specs.append(
            {
                "controlId": cid,
                "mode": effective_mode,
                "property": prop,
                "desired": desired,
            }
        )

    ps = f'''
$ErrorActionPreference = "Stop"

Connect-ExchangeOnline -AppId "{app_id}" `
  -CertificateThumbprint "{thumb}" `
  -Organization "{org}" `
  -ShowBanner:$false

try {{
  $policy = Get-SafeLinksPolicy | Where-Object {{ $_.Name -eq "ATLAS Safe Links Policy" }} | Select-Object -First 1
  if (-not $policy) {{
    $out = @{{ results = @{{}}; error = "missing_atlas_policy" }}
    $out | ConvertTo-Json -Depth 10
    exit
  }}

  $specs = @'
{json.dumps(control_specs)}
'@ | ConvertFrom-Json

  $res = @{{}}

  foreach ($s in $specs) {{
    $cid = $s.controlId
    $prop = $s.property
    $desired = $s.desired
    $mode = $s.mode

    $current = $policy.$prop

    if ($current -eq $desired) {{
      $res[$cid] = @{{ action="no_change"; compliant=$true; current=$current; desired=$desired }}
      continue
    }}

    if ($mode -ne "enforce") {{
      $res[$cid] = @{{ action="report_only_drift"; compliant=$false; current=$current; desired=$desired }}
      continue
    }}

    # enforce
    Set-SafeLinksPolicy -Identity $policy.Identity -ErrorAction Stop @{{ $prop = $desired }} | Out-Null
    $after = Get-SafeLinksPolicy -Identity $policy.Identity
    $afterVal = $after.$prop

    $res[$cid] = @{{ action="set_policy_properties"; compliant=($afterVal -eq $desired); before=$current; after=$afterVal; desired=$desired }}
  }}

  @{{ results = $res }} | ConvertTo-Json -Depth 10
}}
finally {{
  try {{ Disconnect-ExchangeOnline -Confirm:$false }} catch {{}}
}}
'''

    code, stdout, stderr = _run_powershell(ps)
    if code != 0:
        for cid in target_ids:
            results[cid] = ("ERROR", "ENFORCER_ERROR", "PowerShell failed", {"stderr": stderr, "stdout": stdout}, 500)
        ctx["results"] = {**(ctx.get("results") or {}), **results}
        return ctx

    try:
        payload = json.loads(stdout) if stdout else {}
    except Exception:
        for cid in target_ids:
            results[cid] = ("ERROR", "ENFORCER_ERROR", "Failed to parse PowerShell JSON", {"raw_stdout": stdout, "raw_stderr": stderr}, 500)
        ctx["results"] = {**(ctx.get("results") or {}), **results}
        return ctx

    ps_results = payload.get("results") or {}
    results_out = {}
    for cid in target_ids:
        r = ps_results.get(cid)
        if not isinstance(r, dict):
            results_out[cid] = ("ERROR", "ENFORCER_ERROR", "Missing result from bulk runner", {"raw": r}, 500)
            continue

        action = r.get("action") or "unknown"
        compliant = bool(r.get("compliant"))
        details = r

        state = "COMPLIANT" if compliant else "DRIFTED"
        reason = "ENFORCER_EXECUTED" if action in ("set_policy_properties", "no_change") else "REPORT_ONLY_EVALUATED"
        results_out[cid] = (state, reason, "", details, 200)

    ctx["results"] = {**(ctx.get("results") or {}), **results_out}
    return ctx
