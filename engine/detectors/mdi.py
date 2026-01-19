# engine/detectors/mdi.py
from typing import Any, Dict, Optional
import requests
_MDI_CAPABILITY_CACHE: dict[str, dict] = {}


def detect_defender_for_identity_deployed(tenant: Dict[str, Any]) -> Dict[str, Any]:
    """
    DefenderForIdentityDeployed
    Signal: Microsoft Graph Security API - List sensors
      GET https://graph.microsoft.com/v1.0/security/identities/sensors

    Conservative evaluation:
      - COMPLIANT: at least 1 sensor exists
      - DRIFTED: 0 sensors exist
      - NOT_EVALUATED: auth/permission/error
    """
    from engine.auth.token import get_access_token  # existing helper

    url = "https://graph.microsoft.com/v1.0/security/identities/sensors"
    details: Dict[str, Any] = {"endpoint": url}
    tenant_id = (tenant.get("auth") or {}).get("tenant_id") or tenant.get("tenant_id")
    if tenant_id:
        cached = _MDI_CAPABILITY_CACHE.get(tenant_id)
        if isinstance(cached, dict):
            return cached

    try:
        token = get_access_token(tenant)
        if not token:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "AUTH_MISSING",
                "reasonDetail": "No Graph access token available for Microsoft Graph Security API.",
                "details": details,
            }

        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
        details["httpStatus"] = r.status_code

        if r.status_code in (401, 403):
            txt = (r.text or "")
            if "not onboarded" in txt.lower():
                reason_detail = (
                    "Tenant is not onboarded to Microsoft Defender for Identity (MDI). "
                    "After licensing, first login to the MDI portal and sensor onboarding are required."
                )
            else:
                reason_detail = (
                    "Forbidden calling Graph Security sensors API. Ensure the app has Microsoft Graph application "
                    "permission SecurityIdentitiesSensors.Read.All and admin consent is granted."
                )

            result = {
                "state": "NOT_EVALUATED",
                "reasonCode": "AUTH_FORBIDDEN",
                "reasonDetail": reason_detail,
                "details": {**details, "responseText": txt[:2000]},
            }
            if tenant_id:
                _MDI_CAPABILITY_CACHE[tenant_id] = result
            return result




        if r.status_code != 200:
            result = {
                "state": "NOT_EVALUATED",
                "reasonCode": "DETECTOR_ERROR",
                "reasonDetail": f"Graph Security sensors API returned HTTP {r.status_code}",
                "details": {**details, "responseText": (r.text or "")[:2000]},
            }
            if tenant_id:
                _MDI_CAPABILITY_CACHE[tenant_id] = result
            return result



        data = r.json()
        sensors = data.get("value", []) if isinstance(data, dict) else []
        sensor_count = len(sensors)

        # Keep a small, safe sample for troubleshooting
        sample = []
        for s in sensors[:20]:
            if isinstance(s, dict):
                sample.append({
                    "id": s.get("id"),
                    "displayName": s.get("displayName"),
                    "domainName": s.get("domainName"),
                    "sensorType": s.get("sensorType"),
                    "deploymentStatus": s.get("deploymentStatus"),
                    "healthStatus": s.get("healthStatus"),
                    "openHealthIssuesCount": s.get("openHealthIssuesCount"),
                    "version": s.get("version"),
                })

        result = {
            "state": "COMPLIANT" if sensor_count > 0 else "DRIFTED",
            "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
            "reasonDetail": "Evaluated via Microsoft Graph Security API (MDI sensors list).",
            "details": {
                **details,
                "sensorCount": sensor_count,
                "sensorsSample": sample,
            },
        }
        if tenant_id:
            _MDI_CAPABILITY_CACHE[tenant_id] = result
        return result

    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "DETECTOR_ERROR",
            "reasonDetail": f"Exception evaluating DefenderForIdentityDeployed: {e}",
            "details": {**details, "error": str(e)},
        }
