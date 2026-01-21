from __future__ import annotations
from typing import Any, Dict, Tuple, List

from engine.enforcement.graph_singleton import graph_get_json


def _try_catalog(url: str, headers: dict) -> Tuple[int, Dict[str, Any] | None, str | None]:
    return graph_get_json(url, headers=headers, timeout=30)


def detect_auth_methods_catalog(headers: dict) -> Tuple[str, Dict[str, Any]]:
    urls = [
        "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations",
        "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations",
    ]

    attempts: List[Dict[str, Any]] = []

    for url in urls:
        status, body, text = _try_catalog(url, headers)
        attempts.append({
            "url": url,
            "status": status,
            "responseText": (text or "")[:2000],
        })

        if status == 200 and isinstance(body, dict):
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
                "reasonDetail": f"Listed authentication method configurations from {url}.",
                "sourceUrl": url,
                "count": len(catalog),
                "catalog": catalog,
                "attempts": attempts,
            }

        if status == 403:
            # If forbidden on v1.0, beta will likely also be forbidden, but we still record attempts.
            continue

    # If we get here, neither endpoint succeeded.
    # Use the "best" failure from attempts (prefer 403 over 400, else last).
    best = sorted(attempts, key=lambda a: (a["status"] != 403, a["status"] != 400))[0] if attempts else None

    # Classify cleanly
    if best and best["status"] == 403:
        return "NOT_EVALUATED", {
            "reasonCode": "AUTH_FORBIDDEN",
            "reasonDetail": "Graph denied reading authenticationMethodConfigurations.",
            "attempts": attempts,
        }

    return "NOT_EVALUATED", {
        "reasonCode": "UNSUPPORTED_API",
        "reasonDetail": "authenticationMethodConfigurations catalog endpoint not available in this tenant/API shape (v1.0 and beta failed).",
        "attempts": attempts,
    }
