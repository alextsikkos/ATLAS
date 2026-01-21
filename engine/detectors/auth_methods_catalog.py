from __future__ import annotations
from typing import Any, Dict, Tuple

from engine.enforcement.graph_singleton import graph_get_json

def detect_auth_methods_catalog(headers: dict) -> Tuple[str, Dict[str, Any]]:
    url = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations"
    status, body, text = graph_get_json(url, headers=headers, timeout=30)

    if status == 403:
        return "NOT_EVALUATED", {
            "reasonCode": "AUTH_FORBIDDEN",
            "reasonDetail": "Graph denied reading authenticationMethodConfigurations (403).",
            "url": url,
            "status": status,
            "responseText": (text or "")[:2000],
        }
    if status >= 400 or not isinstance(body, dict):
        return "NOT_EVALUATED", {
            "reasonCode": "MISSING_SIGNAL",
            "reasonDetail": f"Failed to query authenticationMethodConfigurations (HTTP {status}).",
            "url": url,
            "status": status,
            "responseText": (text or "")[:2000],
        }

    items = body.get("value") or []
    catalog = []
    for it in items:
        if not isinstance(it, dict):
            continue
        catalog.append({
            "id": it.get("id"),
            "state": it.get("state"),
            "odataType": it.get("@odata.type"),
        })

    return "COMPLIANT", {
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": "Listed authentication method configurations.",
        "count": len(catalog),
        "catalog": catalog,
    }
