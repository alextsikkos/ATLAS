# engine/detectors/auth_methods_probe.py
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

from engine.enforcement.graph_singleton import graph_get_json


CANDIDATE_METHOD_IDS = [
    # Known working in your tenant (already enforced in ATLAS)
    "microsoftAuthenticator",
    "fido2",
    "sms",
    "voice",
    "temporaryAccessPass",

    # Common across tenants (may or may not exist)
    "emailAuthenticationMethod",
    "softwareOath",
    "hardwareOath",
    "windowsHelloForBusiness",
    "passwordlessMicrosoftAuthenticator",
    "x509Certificate",
]


def _probe_one(headers: dict, method_id: str) -> Dict[str, Any]:
    url = (
        "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/"
        f"authenticationMethodConfigurations/{method_id}"
    )
    status, body, text = graph_get_json(url, headers=headers, timeout=20)

    # Capture only small safe bits (avoid dumping huge JSON)
    state = None
    odata_type = None
    if isinstance(body, dict):
        state = body.get("state")
        odata_type = body.get("@odata.type")

    return {
        "id": method_id,
        "url": url,
        "status": status,
        "state": state,
        "odataType": odata_type,
        "responseText": (text or "")[:300],
    }


def detect_auth_methods_probe(headers: dict) -> Tuple[str, Dict[str, Any]]:
    # Parallelize lightly; keep it fast and safe
    max_workers = 8

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(_probe_one, headers, mid) for mid in CANDIDATE_METHOD_IDS]
        for fut in as_completed(futs):
            results.append(fut.result())

    supported = [r for r in results if r.get("status") == 200]
    forbidden = [r for r in results if r.get("status") == 403]
    unsupported = [r for r in results if r.get("status") in (400, 404)]
    other = [r for r in results if r.get("status") not in (200, 400, 403, 404)]

    details: Dict[str, Any] = {
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": "Probed known auth method configuration IDs individually (catalog endpoint not available).",
        "candidates": CANDIDATE_METHOD_IDS,
        "supportedCount": len(supported),
        "forbiddenCount": len(forbidden),
        "unsupportedCount": len(unsupported),
        "otherCount": len(other),
        "supported": [{"id": r["id"], "state": r.get("state"), "odataType": r.get("odataType")} for r in supported],
        "forbidden": [{"id": r["id"], "status": r.get("status")} for r in forbidden],
        "unsupported": [{"id": r["id"], "status": r.get("status")} for r in unsupported],
        "other": other[:10],
    }

    # If everything is forbidden, treat as not evaluated (permissions).
    if len(supported) == 0 and len(forbidden) == len(results):
        return "NOT_EVALUATED", {
            **details,
            "reasonCode": "AUTH_FORBIDDEN",
            "reasonDetail": "Graph denied probing auth method configurations (403 for all candidates).",
        }

    # Otherwise we consider the probe itself successful.
    return "COMPLIANT", details
