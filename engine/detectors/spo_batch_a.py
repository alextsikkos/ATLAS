# engine/detectors/spo_batch_a.py
import json
from typing import Any, Dict, Tuple, Optional

import requests
from msal import ConfidentialClientApplication
_GLOBAL_SWAY_PREFLIGHT_CACHE: dict[str, dict] = {}
_SWAY_CACHE: Dict[str, Dict[str, Any]] = {}


def _norm_bool(v) -> Optional[bool]:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "y", "enabled", "on"):
        return True
    if s in ("false", "0", "no", "n", "disabled", "off"):
        return False
    return None


def detect_sharepoint_guest_users_cannot_reshare(spo_tenant: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps to SharePoint tenant setting: PreventExternalUsersFromResharing
    COMPLIANT when True (guest users cannot reshare).
    """
    val = (spo_tenant or {}).get("PreventExternalUsersFromResharing")
    enabled = _norm_bool(val)

    details = {"PreventExternalUsersFromResharing": val}
    if enabled is None:
        return {
            "state": "NOT_EVALUATED",
            "details": {**details, "missingKeys": ["PreventExternalUsersFromResharing"]},
            "reasonCode": "MISSING_DATA",
            "reasonDetail": "SPO tenant setting missing or not parseable: PreventExternalUsersFromResharing",
        }

    details["PreventExternalUsersFromResharing_normalized"] = enabled
    return {
        "state": "COMPLIANT" if enabled else "DRIFTED",
        "details": details,
    }


def detect_onedrive_block_sync_unmanaged_devices(spo_tenant: Dict[str, Any]) -> Dict[str, Any]:
    """
    Conservative mapping via SPO tenant sync restriction surface:
      - SyncClientRestrictionEnabled
      - AllowedDomainGuids

    We treat COMPLIANT only when SyncClientRestrictionEnabled is explicitly True.
    """
    sync_obj = (spo_tenant or {}).get("TenantSyncClientRestriction") or {}
    tenant_restriction_raw = sync_obj.get("TenantRestrictionEnabled")
    tenant_restriction = _norm_bool(tenant_restriction_raw)
    allowed_domain_list = sync_obj.get("AllowedDomainList")

    # Back-compat fallback (older surface)
    enabled_raw = (spo_tenant or {}).get("SyncClientRestrictionEnabled")
    enabled = _norm_bool(enabled_raw)
    allowed = (spo_tenant or {}).get("AllowedDomainGuids")

    details = {
        "TenantSyncClientRestriction": sync_obj or None,
        "TenantRestrictionEnabled": tenant_restriction_raw,
        "AllowedDomainList": allowed_domain_list,
        "SyncClientRestrictionEnabled": enabled_raw,
        "AllowedDomainGuids": allowed,
    }

    # Prefer the dedicated cmdlet surface when available
    effective = tenant_restriction if tenant_restriction is not None else enabled


    if effective is None:
        return {
            "state": "NOT_EVALUATED",
            "details": {**details, "missingKeys": ["SyncClientRestrictionEnabled"]},
            "reasonCode": "MISSING_DATA",
            "reasonDetail": "SPO tenant setting missing or not parseable: SyncClientRestrictionEnabled",
        }

    details["effectiveRestrictionEnabled_normalized"] = effective
    return {
        "state": "COMPLIANT" if effective else "DRIFTED",
        "details": details,
    }



def _find_external_sharing_bool(obj: Any) -> Optional[Tuple[str, bool]]:
    """
    Heuristic: find a boolean-like field whose key contains both 'external' and 'sharing'.
    Returns (keyPath, value) if found.
    """
    def rec(x: Any, path: str) -> Optional[Tuple[str, bool]]:
        if isinstance(x, dict):
            for k, v in x.items():
                kp = f"{path}.{k}" if path else str(k)
                if isinstance(k, str):
                    lk = k.lower()
                    if ("external" in lk) and ("sharing" in lk):
                        b = _norm_bool(v)
                        if b is not None:
                            return (kp, b)
                hit = rec(v, kp)
                if hit is not None:
                    return hit
        elif isinstance(x, list):
            for i, v in enumerate(x):
                kp = f"{path}[{i}]"
                hit = rec(v, kp)
                if hit is not None:
                    return hit
        return None

    return rec(obj, "")


def detect_sway_block_external_sharing(tenant: Dict[str, Any], timeout_s: int = 30) -> Dict[str, Any]:
    """
    Attempts to read Sway tenant settings via M365 admin center internal settings API:
      GET https://admin.microsoft.com/admin/api/settings/apps/Sway

    Auth attempt order:
      1) client credentials token for https://admin.microsoft.com/.default
      2) fallback to Graph token (may 401; we surface that explicitly)

    COMPLIANT when "external sharing" is effectively disabled (boolean False).
    """
    auth = (tenant or {}).get("auth") or {}
    tenant_id = auth.get("tenant_id")
    client_id = auth.get("client_id")
    client_secret = auth.get("client_secret")
    cache_key = f"{tenant_id}:{client_id}"
    # 1) Preflight fast-fail cache (AUTH_FORBIDDEN etc.)
    cached = _GLOBAL_SWAY_PREFLIGHT_CACHE.get(cache_key)
    if isinstance(cached, dict) and cached.get("fast_fail") is True and isinstance(cached.get("result"), dict):
        return cached["result"]

    # 2) Successful result cache
    cached_ok = _SWAY_CACHE.get(cache_key)
    if isinstance(cached_ok, dict):
        return cached_ok



    url = "https://admin.microsoft.com/admin/api/settings/apps/Sway"

    details: Dict[str, Any] = {
        "endpoint": url,
        "authAttempt": None,
        "httpStatus": None,
    }

    token = None
    # Attempt 1: admin.microsoft.com resource token
    if tenant_id and client_id and client_secret:
        try:
            authority = f"https://login.microsoftonline.com/{tenant_id}"
            app = ConfidentialClientApplication(
                client_id,
                authority=authority,
                client_credential=client_secret,
            )
            tok = app.acquire_token_for_client(scopes=["https://admin.microsoft.com/.default"])
            if "access_token" in tok:
                token = tok["access_token"]
                details["authAttempt"] = "admin.microsoft.com/.default"
            else:
                details["authAttempt"] = "admin.microsoft.com/.default_failed"
                details["tokenError"] = tok
        except Exception as e:
            details["authAttempt"] = "admin.microsoft.com/.default_exception"
            details["tokenException"] = str(e)

    # Attempt 2: fallback to Graph token (best-effort)
    if token is None:
        try:
            from engine.auth.token import get_access_token  # existing helper
            token = get_access_token(tenant)
            details["authAttempt"] = "graph.microsoft.com/.default_fallback"
        except Exception as e:
            return {
                "state": "NOT_EVALUATED",
                "details": {**details, "error": f"Unable to acquire token for Sway settings API: {e}"},
                "reasonCode": "AUTH_MISSING",
                "reasonDetail": "No usable token available for Sway settings API (admin center).",
            }

    try:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=timeout_s)
        details["httpStatus"] = r.status_code

        if r.status_code != 200:
            reason_code = "FALLBACK_DETECTOR_ERROR"
            reason_detail = f"Sway settings API returned HTTP {r.status_code}"

            if r.status_code in (401, 403):
                reason_code = "AUTH_FORBIDDEN"
                reason_detail = "App/token does not have permission to read Sway settings from the Microsoft 365 admin center endpoint."

                result = {
                    "state": "NOT_EVALUATED",
                    "details": {**details, "responseText": (r.text or "")[:4000]},
                    "reasonCode": reason_code,
                    "reasonDetail": reason_detail,
                }
                _GLOBAL_SWAY_PREFLIGHT_CACHE[cache_key] = {"fast_fail": True, "result": result}
                return result



        data = r.json()
        details["raw"] = data  # keep full response for troubleshooting (customer-safe visibility)

        hit = _find_external_sharing_bool(data)
        if hit is None:
            return {
                "state": "NOT_EVALUATED",
                "details": {**details, "missingKeys": ["<external sharing flag not found>"]},
                "reasonCode": "MISSING_DATA",
                "reasonDetail": "Sway settings response did not contain a parseable external sharing flag.",
            }

        key_path, ext_sharing_enabled = hit
        details["externalSharingFlagPath"] = key_path
        details["externalSharingEnabled"] = ext_sharing_enabled

        # Control wants Sways NOT shareable externally => compliant when enabled == False
        result = {
            "state": "COMPLIANT" if (ext_sharing_enabled is False) else "DRIFTED",
            "details": details,
        }
        _SWAY_CACHE[cache_key] = result
        return result


    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "details": {**details, "error": str(e)},
            "reasonCode": "FALLBACK_DETECTOR_ERROR",
            "reasonDetail": "Exception while calling Sway settings API.",
        }
