import json
import os
import subprocess


def _spo_auth_ps_args(tenant_conf: dict) -> tuple[list[str], list[str]]:
    spo_auth = (
        (tenant_conf or {}).get("spoAppAuth")
        or (tenant_conf or {}).get("spoAppOnlyAuth")
        or {}
    )

    client_id = (spo_auth.get("clientId") or spo_auth.get("appId") or "").strip()
    tenant_id = (spo_auth.get("tenantId") or "").strip()
    thumbprint = (spo_auth.get("certificateThumbprint") or "").strip()
    cert_path = (spo_auth.get("certificatePath") or "").strip()
    cert_password = spo_auth.get("certificatePassword")

    missing = []
    if not client_id:
        missing.append("tenant.spoAppAuth.clientId")
    if not tenant_id:
        missing.append("tenant.spoAppAuth.tenantId")
    if not thumbprint and not cert_path:
        missing.append("tenant.spoAppAuth.certificateThumbprint OR certificatePath")
    if cert_path and not (cert_password or "").strip():
        missing.append("tenant.spoAppAuth.certificatePassword")

    if missing:
        return [], missing

    ps_args = ["-ClientId", client_id, "-TenantId", tenant_id]

    if thumbprint:
        ps_args += ["-CertificateThumbprint", thumbprint]
    else:
        ps_args += ["-CertificatePath", cert_path, "-CertificatePassword", str(cert_password)]

    return ps_args, []




def set_spo_domain_restriction(admin_url: str, mode: str, allowed_domains: str | None, blocked_domains: str | None) -> dict:
    if not admin_url or not str(admin_url).strip():
        return {"ok": False, "error": "AdminUrl is required", "adminUrl": admin_url}

    mode = (mode or "").strip()
    if mode not in ("AllowList", "BlockList"):
        return {"ok": False, "error": "Mode must be AllowList or BlockList", "mode": mode}

    ps1_path = os.path.join(os.path.dirname(__file__), "spo_set_domain_restriction.ps1")

    auth_args, missing_keys = _spo_auth_ps_args(tenant_conf)
    result["authMode"] = "app-only" if auth_args else "interactive-disabled"
    result["authArgsPresent"] = bool(auth_args)

    if missing_keys:
        return {"ok": False, "error": "SPO app-only auth is configured but missing required keys; refusing to fall back to interactive auth", "missingKeys": missing_keys, "adminUrl": admin_url}

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ps1_path,
        "-AdminUrl", str(admin_url).strip(),
        "-Mode", mode,
        "-AllowedDomains", (allowed_domains or ""),
        "-BlockedDomains", (blocked_domains or ""),
    ] + auth_args

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        return {"ok": False, "error": f"Failed to execute PowerShell: {e}", "cmd": cmd}

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()

    if proc.returncode != 0:
        return {
            "ok": False,
            "error": "Set-SPOTenant domain restriction failed",
            "stdout": out,
            "stderr": err,
            "exitCode": proc.returncode,
            "cmd": cmd,
        }

    return {
        "ok": True,
        "stdout": out,
        "stderr": err if err else None,
        "exitCode": proc.returncode,
        "adminUrl": str(admin_url).strip(),
        "mode": mode,
        "allowedDomains": allowed_domains,
        "blockedDomains": blocked_domains,
    }
def set_spo_tenant_settings_bulk(admin_url: str, settings: dict) -> dict:
    """Apply multiple Set-SPOTenant parameters in a *single* call.

    settings is a dict of Set-SPOTenant parameter name -> value.
    Values should be JSON-serializable.
    """
    if not admin_url or not str(admin_url).strip():
        return {"ok": False, "error": "AdminUrl is required", "adminUrl": admin_url}

    if not isinstance(settings, dict) or not settings:
        return {"ok": False, "error": "settings must be a non-empty dict", "settings": settings}

    ps1_path = os.path.join(os.path.dirname(__file__), "spo_set_tenant_settings_bulk.ps1")

    auth_args, missing_keys = _spo_auth_ps_args(tenant_conf)
    result["authMode"] = "app-only" if auth_args else "interactive-disabled"
    result["authArgsPresent"] = bool(auth_args)

    if missing_keys:
        return {
            "ok": False,
            "error": "SPO app-only auth is configured but missing required keys; refusing to fall back to interactive auth",
            "missingKeys": missing_keys,
            "adminUrl": admin_url,
        }

    try:
        settings_json = json.dumps(settings)
    except Exception as e:
        return {"ok": False, "error": f"Failed to JSON-serialize settings: {e}", "settings": settings}

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ps1_path,
        "-AdminUrl", str(admin_url).strip(),
        "-SettingsJson", settings_json,
    ] + auth_args

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        return {"ok": False, "error": f"Failed to execute PowerShell: {e}", "cmd": cmd}

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()

    if proc.returncode != 0:
        return {
            "ok": False,
            "error": "Set-SPOTenant bulk update failed",
            "stdout": out,
            "stderr": err,
            "exitCode": proc.returncode,
            "cmd": cmd,
            "adminUrl": str(admin_url).strip(),
            "settings": settings,
        }

    return {
        "ok": True,
        "stdout": out,
        "stderr": err if err else None,
        "exitCode": proc.returncode,
        "adminUrl": str(admin_url).strip(),
        "settings": settings,
    }
