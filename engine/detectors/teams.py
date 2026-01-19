import json
import subprocess
from pathlib import Path

def run_teams_tenant_settings(tenant_id: str, app_id: str, certificate_thumbprint: str) -> dict:
    """Fetch Teams tenant configuration via MicrosoftTeams PowerShell.

    Returns a dict:
      - { ok: True, tenant: {...} } on success
      - { ok: False, error: "..." } on failure
    """
    script_path = Path(__file__).resolve().parent / "teams_tenant_settings.ps1"

    ps_cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", str(script_path),
        "-TenantId", tenant_id,
        "-AppId", app_id,
        "-CertificateThumbprint", certificate_thumbprint,
    ]

    proc = subprocess.run(ps_cmd, capture_output=True, text=True)
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()

    if proc.returncode != 0:
        return {"ok": False, "error": err or f"PowerShell exited with {proc.returncode}"}

    try:
        data = json.loads(out) if out else {}
        if not isinstance(data, dict):
            return {"ok": False, "error": "Unexpected Teams detector output (not a JSON object)"}
        if err:
            data["stderr"] = err
        return data
    except Exception as e:
        return {"ok": False, "error": f"Failed to parse Teams detector JSON: {e}", "raw": out, "stderr": err}
