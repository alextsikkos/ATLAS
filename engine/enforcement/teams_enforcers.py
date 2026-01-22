# engine/enforcement/teams_enforcers.py
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Tuple

from engine.enforcement.registry import register


def _run_powershell_file(ps1_path: Path, args: list[str], timeout: int = 300) -> Tuple[int, str, str]:
    ps_cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(ps1_path)] + args
    proc = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


def _parse_json(s: str) -> dict:
    try:
        d = json.loads(s) if s else {}
        return d if isinstance(d, dict) else {"ok": False, "error": "Unexpected JSON (not an object)", "raw": s}
    except Exception as e:
        return {"ok": False, "error": f"Failed to parse JSON: {e}", "raw": s}


def _get_teams_app_auth(tenant: dict) -> tuple[dict | None, dict | None]:
    # Mirror the detector expectations (tenantId/appId/certificateThumbprint)
    # Detector uses Connect-MicrosoftTeams -TenantId -ApplicationId -CertificateThumbprint. :contentReference[oaicite:1]{index=1}
    cfg = (tenant or {}).get("teamsAppAuth") or {}
    if not isinstance(cfg, dict) or not cfg:
        return None, {"reason": "Missing teamsAppAuth in tenant JSON"}

    tenant_id = (cfg.get("tenantId") or "").strip()
    app_id = (cfg.get("appId") or "").strip()
    thumb = (cfg.get("certificateThumbprint") or "").strip()

    missing = [k for k, v in [("tenantId", tenant_id), ("appId", app_id), ("certificateThumbprint", thumb)] if not v]
    if missing:
        return None, {"reason": f"teamsAppAuth missing required keys: {', '.join(missing)}"}

    return {"tenantId": tenant_id, "appId": app_id, "thumb": thumb}, None


def _enforce_teams_external_access_restricted(**kwargs):
    """
    Control: TeamsExternalAccessRestricted

    Enforces 'restricted' stance on Global External Access Policy:
      - EnableFederationAccess = False
      - EnablePublicCloudAccess = False
      - EnableTeamsConsumerAccess = False
      - EnableTeamsConsumerInbound = False

    Conservative: if cmdlets are unavailable, returns NOT_EVALUATED with reason.
    """
    tenant = kwargs["tenant"]
    mode = (kwargs.get("mode") or "report-only").strip().lower()

    cfg, err = _get_teams_app_auth(tenant)
    if err:
        return ("ERROR", "MISSING_PREREQUISITE", err["reason"], {"error": err}, 400)

    script_path = Path(__file__).resolve().parent / "teams_set_external_access_restricted.ps1"
    args = [
        "-TenantId", cfg["tenantId"],
        "-AppId", cfg["appId"],
        "-CertificateThumbprint", cfg["thumb"],
        "-Mode", mode,
    ]

    rc, out, ps_err = _run_powershell_file(script_path, args=args, timeout=300)
    data = _parse_json(out)

    if rc != 0 or not data.get("ok"):
        return (
            "NOT_EVALUATED",
            "ENFORCER_ERROR",
            "Teams external access enforcer failed",
            {"powershellExitCode": rc, "stderr": ps_err, "result": data},
            502,
        )

    # data contains: applied(bool), before, after, verify, changed(list)
    applied = bool(data.get("applied"))
    verify_ok = bool((data.get("verify") or {}).get("ok"))

    # Report-only path: do not enforce
    if mode in ("report-only", "detect-only"):
        state = "COMPLIANT" if verify_ok else "DRIFTED"
        return (
            state,
            "REPORT_ONLY_EVALUATED",
            "Report-only: evaluated Teams external access policy (no changes applied)",
            data,
            200,
        )

    # Enforce path:
    if verify_ok:
        return (
            "COMPLIANT",
            "ENFORCER_EXECUTED",
            "Enforcer executed; Teams external access restricted as required",
            data,
            200,
        )

    # Enforcer ran but verify failed
    return (
        "DRIFTED",
        "ENFORCER_EXECUTED",
        "Enforcer ran but verification still shows external access not restricted",
        data,
        207,
    )


register("TeamsExternalAccessRestricted", _enforce_teams_external_access_restricted)
