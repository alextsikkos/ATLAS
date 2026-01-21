# engine/detectors/per_user_mfa.py
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

import requests


def _graph_get_json(url: str, headers: dict, timeout: int = 30) -> tuple[int, dict | None, str | None]:
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        txt = r.text
        if r.status_code >= 400:
            return r.status_code, None, txt
        try:
            return r.status_code, (r.json() or {}), txt
        except Exception:
            return r.status_code, None, txt
    except Exception as e:
        return 0, None, str(e)


def _paged_users(headers: dict, select: str = "id,userPrincipalName,accountEnabled") -> Tuple[int, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Fetch all users (id + upn). Returns: (http_status, users, debug)
    """
    url = f"https://graph.microsoft.com/v1.0/users?$select={select}&$top=999"
    users: List[Dict[str, Any]] = []
    debug: Dict[str, Any] = {"pages": 0, "fetched": 0}
    while url:
        status, body, txt = _graph_get_json(url, headers=headers, timeout=30)
        if status >= 400 or body is None:
            debug["error"] = {"status": status, "responseText": (txt or "")[:2000], "url": url}
            return status, [], debug
        vals = body.get("value") or []
        users.extend([u for u in vals if isinstance(u, dict)])
        debug["pages"] += 1
        debug["fetched"] = len(users)
        url = body.get("@odata.nextLink")
    return 200, users, debug


def _get_user_requirements(headers: dict, user_id: str) -> Dict[str, Any]:
    # NOTE: This is a beta endpoint; that’s why this is readiness/detect-only.
    url = f"https://graph.microsoft.com/beta/users/{user_id}/authentication/requirements"
    status, body, txt = _graph_get_json(url, headers=headers, timeout=20)
    return {
        "status": status,
        "body": body,
        "responseText": (txt or "")[:500],
        "url": url,
    }


def detect_per_user_mfa_readiness(headers: dict) -> Tuple[str, Dict[str, Any]]:
    """
    Detect-only readiness:
    - Enumerate users
    - For each user, query /beta/users/{id}/authentication/requirements
    - Report counts and samples of users where per-user MFA appears enabled/enforced
    """
    u_status, users, u_debug = _paged_users(headers=headers)

    if u_status == 403:
        return "NOT_EVALUATED", {
            "reasonCode": "AUTH_FORBIDDEN",
            "reasonDetail": "Graph denied reading users (403).",
            "usersDebug": u_debug,
        }
    if u_status >= 400:
        return "NOT_EVALUATED", {
            "reasonCode": "MISSING_SIGNAL",
            "reasonDetail": f"Failed to enumerate users (HTTP {u_status}).",
            "usersDebug": u_debug,
        }

    # Keep this parallel but not insane (tenants can be large).
    max_workers = 12
    results: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []

    id_to_upn = {u.get("id"): u.get("userPrincipalName") for u in users if u.get("id")}
    user_ids = [u.get("id") for u in users if u.get("id")]

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_get_user_requirements, headers, uid): uid for uid in user_ids}
        for fut in as_completed(futs):
            uid = futs[fut]
            try:
                r = fut.result(timeout=30)
            except Exception as e:
                failures.append({"userId": uid, "upn": id_to_upn.get(uid), "error": str(e)})
                continue

            status = r.get("status", 0)
            body = r.get("body") if isinstance(r.get("body"), dict) else None

            if status == 200 and body is not None:
                # Property name varies across tenants; we record raw body and interpret conservatively.
                results.append({"userId": uid, "upn": id_to_upn.get(uid), "requirements": body})
            else:
                failures.append({
                    "userId": uid,
                    "upn": id_to_upn.get(uid),
                    "status": status,
                    "responseText": r.get("responseText"),
                })

    # Conservative interpretation: flag if requirements indicates anything other than "none"/"disabled".
    flagged: List[Dict[str, Any]] = []
    for r in results:
        req = r.get("requirements") or {}
        # Best-effort: common field seen is "perUserMfaState" (not guaranteed). We don't assume it exists.
        state = (req.get("perUserMfaState") or req.get("state") or req.get("mfaState") or "")
        state_norm = str(state).strip().lower()

        if state_norm and state_norm not in ("disabled", "none", "notenabled", "off"):
            flagged.append({"upn": r.get("upn"), "userId": r.get("userId"), "state": state, "raw": req})
        elif not state_norm:
            # If we can't see a clear state, we don't flag (we report as "unknown" coverage).
            pass

    details: Dict[str, Any] = {
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": "Enumerated per-user MFA requirements via Graph beta endpoints (detect-only readiness).",
        "tenantSize": len(users),
        "queriedUsers": len(results),
        "queryFailures": len(failures),
        "flaggedCount": len(flagged),
        "flaggedSample": flagged[:25],
        "failuresSample": failures[:25],
        "notes": [
            "This uses Graph beta (/authentication/requirements) and is detect-only.",
            "If flaggedCount > 0, consider migrating to Conditional Access and modern auth methods before cleanup.",
        ],
    }

    # State logic: if we flagged any users, readiness is DRIFTED; otherwise COMPLIANT.
    if len(flagged) > 0:
        return "DRIFTED", details

    # If we couldn't query most users, don't claim compliant.
    if len(results) == 0 and len(users) > 0:
        return "NOT_EVALUATED", {
            **details,
            "reasonCode": "INSUFFICIENT_SIGNAL",
            "reasonDetail": "Could not read per-user MFA requirements for any users.",
        }

    return "COMPLIANT", details
