import json
import os
import subprocess


def _spo_auth_ps_args(tenant_conf: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Build PS args for SPO auth from the tenant JSON (NOT env vars).

    Supported tenant keys:
      - tenant_conf["spoAppAuth"] or tenant_conf["spoAppOnlyAuth"]
        with:
          - clientId (or appId)
          - tenantId
          - certificateThumbprint   OR
          - certificatePath + certificatePassword
    """
    spo_auth = tenant_conf.get("spoAppAuth") or tenant_conf.get("spoAppOnlyAuth") or {}

    client_id = spo_auth.get("clientId") or spo_auth.get("appId")
    tenant_id = spo_auth.get("tenantId")
    thumbprint = spo_auth.get("certificateThumbprint")
    cert_path = spo_auth.get("certificatePath")
    cert_password = spo_auth.get("certificatePassword")

    missing: List[str] = []
    if not client_id:
        missing.append("spoAppAuth.clientId")
    if not tenant_id:
        missing.append("spoAppAuth.tenantId")

    has_thumbprint = bool(thumbprint and str(thumbprint).strip())
    has_path_mode = bool(cert_path and str(cert_path).strip())

    if not has_thumbprint and not has_path_mode:
        missing.append("spoAppAuth.certificateThumbprint OR spoAppAuth.certificatePath")

    if has_path_mode and not (cert_password and str(cert_password).strip()):
        missing.append("spoAppAuth.certificatePassword (required when using certificatePath)")

    if missing:
        return [], missing

    args: List[str] = ["-ClientId", str(client_id), "-TenantId", str(tenant_id)]

    if has_thumbprint:
        args += ["-CertificateThumbprint", str(thumbprint)]
    else:
        args += ["-CertificatePath", str(cert_path), "-CertificatePassword", str(cert_password)]

    return args, []


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
