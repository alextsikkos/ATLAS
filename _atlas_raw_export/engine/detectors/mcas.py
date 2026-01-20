# engine/detectors/mcas.py
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import requests

try:
    from msal import ConfidentialClientApplication
except Exception:  # pragma: no cover
    ConfidentialClientApplication = None  # type: ignore


MCAS_AUDIENCE_APP_ID_URI = "05a65629-4c1b-48c1-a78b-804c4abdd4af"


def _get_tenant_auth(tenant: dict) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Returns (tenant_id, client_id, client_secret) from tenant config.
    We intentionally do NOT guess / fallback to interactive auth.
    """
    auth = (tenant or {}).get("auth") or {}
    tenant_id = auth.get("tenant_id") or auth.get("tenantId")
    client_id = auth.get("client_id") or auth.get("clientId")
    client_secret = auth.get("client_secret") or auth.get("clientSecret")

    tenant_id = tenant_id.strip() if isinstance(tenant_id, str) else tenant_id
    client_id = client_id.strip() if isinstance(client_id, str) else client_id
    client_secret = client_secret.strip() if isinstance(client_secret, str) else client_secret

    return tenant_id, client_id, client_secret


def _get_mcas_api_base(tenant: dict) -> Optional[str]:
    """
    Expected: a portal base like:
      https://<tenant>.<region>.portal.cloudappsecurity.com
    We normalize to:
      https://.../api
    """
    mcas = (tenant or {}).get("mcas") or {}
    api_url = (
        mcas.get("apiUrl")
        or mcas.get("api_url")
        or mcas.get("portalUrl")
        or mcas.get("portal_url")
        or (tenant or {}).get("mcasApiUrl")
        or (tenant or {}).get("mcasPortalUrl")
    )

    if not isinstance(api_url, str):
        return None

    api_url = api_url.strip().rstrip("/")
    if not api_url:
        return None

    # If someone pasted ".../api", keep it. Otherwise append "/api".
    if api_url.lower().endswith("/api"):
        return api_url
    return f"{api_url}/api"


def _acquire_mcas_app_token(tenant_id: str, client_id: str, client_secret: str) -> Tuple[Optional[str], Dict[str, Any]]:
    details: Dict[str, Any] = {
        "authority": f"https://login.microsoftonline.com/{tenant_id}",
        "audience": MCAS_AUDIENCE_APP_ID_URI,
        "tokenMethod": "msal.acquire_token_for_client",
    }

    if ConfidentialClientApplication is None:
        return None, {**details, "error": "msal is not available in this environment"}

    app = ConfidentialClientApplication(
        client_id=client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )

    # App-only scopes per Microsoft docs for MCAS audience
    tok = app.acquire_token_for_client(scopes=[f"{MCAS_AUDIENCE_APP_ID_URI}/.default"])
    if "access_token" in tok:
        return tok["access_token"], {**details, "tokenResult": "ok"}
    return None, {**details, "tokenResult": "failed", "tokenError": tok}


def detect_mcas_firewall_log_upload_configured(tenant: dict) -> dict:
    """
    Control: McasFirewallLogUpload (Secure Score)
    Detect-only via Defender for Cloud Apps Cloud Discovery API:
      GET api/discovery/streams/

    Conservative rules:
      - NOT_EVALUATED if auth or MCAS API URL missing, or API call fails
      - DRIFTED if streams list is empty
      - COMPLIANT if streams list has >= 1 stream
    """
    details: Dict[str, Any] = {
        "endpoint": None,
        "httpStatus": None,
        "streamCount": None,
        "streamNamesSample": [],
        "missingKeys": [],
    }

    api_base = _get_mcas_api_base(tenant)
    if not api_base:
        details["missingKeys"].append("tenant.mcas.apiUrl (or portalUrl)")
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "AUTH_MISSING",
            "reasonDetail": "MCAS API base URL missing from tenant config (mcas.apiUrl / mcas.portalUrl).",
            "details": details,
        }

    tenant_id, client_id, client_secret = _get_tenant_auth(tenant)
    if not (tenant_id and client_id and client_secret):
        if not tenant_id:
            details["missingKeys"].append("tenant.auth.tenant_id")
        if not client_id:
            details["missingKeys"].append("tenant.auth.client_id")
        if not client_secret:
            details["missingKeys"].append("tenant.auth.client_secret")
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "AUTH_MISSING",
            "reasonDetail": "Missing app-only auth fields required to call Defender for Cloud Apps API.",
            "details": details,
        }

    token, token_details = _acquire_mcas_app_token(str(tenant_id), str(client_id), str(client_secret))
    details["token"] = token_details
    if not token:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "AUTH_FORBIDDEN",
            "reasonDetail": "Unable to acquire Defender for Cloud Apps app-only token.",
            "details": details,
        }

    url = f"{api_base}/discovery/streams/"
    details["endpoint"] = url

    try:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
        details["httpStatus"] = r.status_code

        if r.status_code != 200:
            reason_code = "FALLBACK_DETECTOR_ERROR"
            reason_detail = f"MCAS API returned HTTP {r.status_code}"
            if r.status_code in (401, 403):
                reason_code = "AUTH_FORBIDDEN"
                reason_detail = "Token does not have permission to call MCAS discovery streams API."
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": reason_code,
                "reasonDetail": reason_detail,
                "details": {**details, "responseText": (r.text or "")[:4000]},
            }

        data = r.json()

        # Docs show either a single object or a list; normalize to list.
        streams = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
        details["streamCount"] = len(streams)

        # keep only a small sample
        names = []
        for s in streams[:10]:
            if isinstance(s, dict):
                n = s.get("displayName")
                if n:
                    names.append(n)
        details["streamNamesSample"] = names

        if len(streams) == 0:
            return {
                "state": "DRIFTED",
                "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
                "reasonDetail": "No Cloud Discovery continuous reports (streams) found in Defender for Cloud Apps.",
                "details": details,
            }

        return {
            "state": "COMPLIANT",
            "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
            "reasonDetail": "Cloud Discovery continuous reports (streams) exist in Defender for Cloud Apps.",
            "details": details,
        }

    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "FALLBACK_DETECTOR_ERROR",
            "reasonDetail": "Exception while calling MCAS discovery streams API.",
            "details": {**details, "error": str(e)},
        }
