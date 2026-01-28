import json
import os
import subprocess


def _spo_auth_ps_args() -> tuple[list[str], list[str]]:
    client_id = (os.getenv("ATLAS_SPO_CLIENT_ID") or "").strip()
    tenant_id = (os.getenv("ATLAS_SPO_TENANT_ID") or "").strip()
    thumbprint = (os.getenv("ATLAS_SPO_CERT_THUMBPRINT") or "").strip()
    cert_path = (os.getenv("ATLAS_SPO_CERT_PATH") or "").strip()
    cert_password = os.getenv("ATLAS_SPO_CERT_PASSWORD")

    missing = []
    if not client_id:
        missing.append("tenant.spoAppAuth.clientId")
    if not tenant_id:
        missing.append("tenant.spoAppAuth.tenantId")
    if not thumbprint and not cert_path:
        missing.append("tenant.spoAppAuth.certificateThumbprint OR certificatePath")
    if cert_path and not str(cert_password).strip():
        missing.append("tenant.spoAppAuth.certificatePassword")

    if missing:
        return [], missing

    ps_args = ["-ClientId", client_id, "-TenantId", tenant_id]

    if thumbprint:
        ps_args += ["-CertificateThumbprint", thumbprint]
    else:
        ps_args += ["-CertificatePath", cert_path, "-CertificatePassword", str(cert_password)]

    return ps_args, []

def set_spo_browser_idle_signout(
    admin_url: str,
    enabled: bool,
    warn_after_seconds: int,
    signout_after_seconds: int,
) -> dict:
    if not admin_url or not str(admin_url).strip():
        return {"ok": False, "error": "AdminUrl is required", "adminUrl": admin_url}

    ps1_path = os.path.join(os.path.dirname(__file__), "spo_set_browser_idle_signout.ps1")

    auth_args, missing_keys = _spo_auth_ps_args()
    if missing_keys:
        return {
            "ok": False,
            "error": "SPO app-only auth is configured but missing required keys; refusing to fall back to interactive auth",
            "missingKeys": missing_keys,
            "adminUrl": admin_url,
        }

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ps1_path,
        "-AdminUrl", str(admin_url).strip(),
        "-Enabled", str(bool(enabled)).lower(),
        "-WarnAfterSeconds", str(int(warn_after_seconds)),
        "-SignOutAfterSeconds", str(int(signout_after_seconds)),
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
            "error": "Set-SPOBrowserIdleSignOut failed",
            "stdout": out,
            "stderr": err,
            "exitCode": proc.returncode,
            "cmd": cmd,
        }

    try:
        return json.loads(out) if out else {"ok": True}
    except Exception:
        return {"ok": True, "raw": out, "stderr": err or None}

def run_spo_tenant_settings(admin_url: str) -> dict:


    if not admin_url or not str(admin_url).strip():
        return {
            "ok": False,
            "error": "AdminUrl is required (e.g. https://contoso-admin.sharepoint.com)",
            "tenant": None,
            "adminUrl": admin_url,
        }

    ps1_path = os.path.join(os.path.dirname(__file__), "spo_tenant_settings.ps1")

    auth_args, missing_keys = _spo_auth_ps_args()
    if missing_keys:
        return {
            "ok": False,
            "error": "SPO app-only auth is configured but missing required keys; refusing to fall back to interactive auth",
            "missingKeys": missing_keys,
            "tenant": None,
            "adminUrl": admin_url,
        }

    cmd = [

        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-NoLogo",
        "-ExecutionPolicy", "Bypass",
        "-File", ps1_path,
        "-AdminUrl", str(admin_url).strip(),
    ] + auth_args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "error": "PowerShell timed out (SPO runner hung)",
            "cmd": cmd,
            "stdout": (e.stdout or "").strip() if hasattr(e, "stdout") else None,
            "stderr": (e.stderr or "").strip() if hasattr(e, "stderr") else None,
            "timeoutSeconds": 180,
        }
    except Exception as e:
        return {"ok": False, "error": f"Failed to execute PowerShell: {e}", "cmd": cmd}


    out = proc.stdout or ""
    err = proc.stderr or ""
    raw = out.strip()

    # PowerShell can emit warnings before JSON; extract the JSON object.
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {
            "ok": False,
            "error": "No JSON object found in SPO output",
            "raw": raw,
            "stderr": err,
            "exitCode": proc.returncode,
        }

    json_text = raw[start:end + 1]

    try:
        data = json.loads(json_text)
    except Exception as e:
        return {
            "ok": False,
            "error": f"Failed to parse SPO detector JSON: {e}",
            "raw": raw,
            "stderr": err,
            "exitCode": proc.returncode,
        }

    if err:
        data["stderr"] = err
    data.setdefault("exitCode", proc.returncode)

    return data
def set_spo_prevent_external_users_from_resharing(admin_url: str, enabled: bool) -> dict:
    """
    Applies: Set-SPOTenant -PreventExternalUsersFromResharing $true/$false
    Returns a dict like run_spo_tenant_settings: {"ok": bool, "error": str|None, ...}
    """
    if not admin_url or not str(admin_url).strip():
        return {
            "ok": False,
            "error": "AdminUrl is required (e.g. https://contoso-admin.sharepoint.com)",
            "adminUrl": admin_url,
        }

    ps1_path = os.path.join(os.path.dirname(__file__), "spo_set_prevent_resharing.ps1")

    auth_args, missing_keys = _spo_auth_ps_args()

    if missing_keys:
        return {
            "ok": False,
            "error": "SPO app-only auth is configured but missing required keys; refusing to fall back to interactive auth",
            "missingKeys": missing_keys,
            "adminUrl": admin_url,
        }

    # Powershell boolean literal
    enabled_ps = "$true" if bool(enabled) else "$false"

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-NoLogo",
        "-ExecutionPolicy", "Bypass",
        "-File", ps1_path,
        "-AdminUrl", str(admin_url).strip(),
        "-Enabled", enabled_ps,
    ] + auth_args

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "error": "PowerShell timed out (SPO runner hung)",
            "cmd": cmd,
            "stdout": (e.stdout or "").strip() if hasattr(e, "stdout") else None,
            "stderr": (e.stderr or "").strip() if hasattr(e, "stderr") else None,
            "timeoutSeconds": 180,
        }
    except Exception as e:
        return {"ok": False, "error": f"Failed to execute PowerShell: {e}", "cmd": cmd}


    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()

    # Keep it conservative: if exit code != 0, return error even if stdout exists
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": "SPO Set-SPOTenant command failed",
            "stdout": out,
            "stderr": err,
            "exitCode": proc.returncode,
            "cmd": cmd,
        }

    return {
        "ok": True,
        "error": None,
        "stdout": out,
        "stderr": err if err else None,
        "exitCode": proc.returncode,
        "adminUrl": str(admin_url).strip(),
        "enabled": bool(enabled),
    }

def set_spo_domain_restriction(admin_url: str, mode: str, allowed_domains: str | None, blocked_domains: str | None) -> dict:
    if not admin_url or not str(admin_url).strip():
        return {"ok": False, "error": "AdminUrl is required", "adminUrl": admin_url}

    mode = (mode or "").strip()
    if mode not in ("AllowList", "BlockList"):
        return {"ok": False, "error": "Mode must be AllowList or BlockList", "mode": mode}

    ps1_path = os.path.join(os.path.dirname(__file__), "spo_set_domain_restriction.ps1")

    auth_args, missing_keys = _spo_auth_ps_args()
    if missing_keys:
        return {"ok": False, "error": "SPO app-only auth is configured but missing required keys; refusing to fall back to interactive auth", "missingKeys": missing_keys, "adminUrl": admin_url}

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-NoLogo",
        "-ExecutionPolicy", "Bypass",
        "-File", ps1_path,
        "-AdminUrl", str(admin_url).strip(),
        "-Mode", mode,
        "-AllowedDomains", (allowed_domains or ""),
        "-BlockedDomains", (blocked_domains or ""),
    ] + auth_args

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "error": "PowerShell timed out (SPO runner hung)",
            "cmd": cmd,
            "stdout": (e.stdout or "").strip() if hasattr(e, "stdout") else None,
            "stderr": (e.stderr or "").strip() if hasattr(e, "stderr") else None,
            "timeoutSeconds": 180,
        }
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

    auth_args, missing_keys = _spo_auth_ps_args()
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
        "-NonInteractive",
        "-NoLogo",
        "-ExecutionPolicy", "Bypass",
        "-File", ps1_path,
        "-AdminUrl", str(admin_url).strip(),
        "-SettingsJson", settings_json,
    ] + auth_args

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "error": "PowerShell timed out (SPO runner hung)",
            "cmd": cmd,
            "stdout": (e.stdout or "").strip() if hasattr(e, "stdout") else None,
            "stderr": (e.stderr or "").strip() if hasattr(e, "stderr") else None,
            "timeoutSeconds": 180,
        }
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
