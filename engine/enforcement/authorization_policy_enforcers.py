# engine/enforcement/authorization_policy_enforcers.py
from __future__ import annotations

import time
import requests
from typing import Any, Dict, Tuple

from engine.enforcement.registry import register
from engine.auth.token import get_access_token


AUTHZ_URL = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"


def _get_authz(headers: dict) -> Tuple[int, dict | None, str]:
    r = requests.get(AUTHZ_URL, headers=headers, timeout=30)
    txt = r.text or ""
    try:
        return r.status_code, (r.json() if txt.strip() else None), txt
    except Exception:
        return r.status_code, None, txt


def _patch_authz(headers: dict, payload: dict) -> Tuple[int, dict | None, str]:
    r = requests.patch(AUTHZ_URL, headers=headers, json=payload, timeout=30)
    txt = r.text or ""
    try:
        return r.status_code, (r.json() if txt.strip() else None), txt
    except Exception:
        return r.status_code, None, txt


def _verify(get_fn, is_desired_fn, attempts: int = 5, delay_seconds: float = 2.0):
    last = (0, None, "")
    for i in range(1, attempts + 1):
        last = get_fn()
        status, body, text = last
        if status < 400 and isinstance(body, dict) and is_desired_fn(body):
            return status, body, text, i
        time.sleep(delay_seconds)
    return last[0], last[1], last[2], attempts


def _enforce_authz_bool(
    *,
    tenant: dict,
    control_id: str,
    approval: dict | None,
    mode: str,
    get_current_value_fn,
    desired_payload: dict | None,
    desired_value: Any,
    build_payload_fn=None,
) -> Tuple[str, str, str, dict, int]:
    token = get_access_token(tenant)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    b_status, b_body, b_text = _get_authz(headers)
    if b_status >= 400 or not isinstance(b_body, dict):
        return (
            "NOT_EVALUATED",
            "AUTH_FORBIDDEN" if b_status == 403 else "MISSING_SIGNAL",
            f"Graph GET authorizationPolicy failed (HTTP {b_status})",
            {"url": AUTHZ_URL, "status": b_status, "responseText": (b_text or "")[:2000]},
            b_status,
        )

    before_val = get_current_value_fn(b_body)
    evidence_key = control_id  # always use the actual controlId being audited

    details = {
        "url": AUTHZ_URL,
        "before": {evidence_key: before_val},
        "desired": {evidence_key: desired_value},
    }
    # If already desired, do not write (idempotent + avoids empty/incorrect payload writes)
    if before_val == desired_value:
        if mode == "enforce":
            return ("COMPLIANT", "ENFORCER_EXECUTED", "Already in desired state; no changes applied", details, 200)
        return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: already matches desired", details, 200)

    # report-only
    if mode != "enforce":
        if before_val == desired_value:
            return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: already matches desired", details, 200)
        return ("DRIFTED", "REPORT_ONLY_EVALUATED", "Report-only: drift detected", details, 200)
    # Compute payload after GET if caller requested preserve semantics
    if desired_payload is None:
        if callable(build_payload_fn):
            desired_payload = build_payload_fn(b_body)
        else:
            # Defensive: never send an empty/incorrect payload
            return (
                "ERROR",
                "ENFORCER_ERROR",
                "No desired_payload provided and no build_payload_fn supplied",
                details,
                500,
            )


    # enforce: apply patch
    a_status, a_body, a_text = _patch_authz(headers, desired_payload)
    details["apply"] = {
        "status": a_status,
        "responseText": (a_text or "")[:2000] if a_text else None,
        "applied": desired_payload,
    }

    if a_status >= 400:
        return (
            "ERROR",
            "ENFORCER_ERROR",
            f"Graph PATCH authorizationPolicy failed (HTTP {a_status})",
            details,
            a_status,
        )

    def _get():
        return _get_authz(headers)

    def _is_desired(body: dict) -> bool:
        return get_current_value_fn(body) == desired_value

    v_status, v_body, v_text, attempt = _verify(_get, _is_desired, attempts=5, delay_seconds=2.0)
    after_val = get_current_value_fn(v_body) if isinstance(v_body, dict) else None

    details["verify"] = {"status": v_status, "attempt": attempt, "responseText": (v_text or "")[:2000]}
    details["after"] = {evidence_key: after_val}

    if after_val == desired_value:
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforcer executed; post-state verified", details, 200)

    return ("DRIFTED", "ENFORCER_EXECUTED", "Enforcer executed; desired state not observed after verify", details, 200)


# =========================
# AdminOwnedAppsRestricted
# =========================
def _admin_owned_apps_restricted(**kwargs):
    tenant = kwargs["tenant"]
    approval = kwargs.get("approval")
    mode = (kwargs.get("mode") or "report-only").strip().lower()

    def _cur(ap: dict):
        return (ap.get("defaultUserRolePermissions") or {}).get("allowedToCreateApps", None)

    # Preserve whole object so PATCH doesn't accidentally wipe other perms
    def _payload_from(ap: dict) -> dict:
        durp = (ap.get("defaultUserRolePermissions") or {}).copy()
        durp["allowedToCreateApps"] = False
        return {"defaultUserRolePermissions": durp}

    return _enforce_authz_bool(
        tenant=tenant,
        control_id="AdminOwnedAppsRestricted",
        approval=approval,
        mode=mode,
        get_current_value_fn=_cur,
        desired_payload=None,              # <-- computed from current object
        desired_value=False,
        build_payload_fn=_payload_from,    # <-- ensures safe patch semantics
    )

# =========================
# IntegratedAppsRestricted
# =========================
def _integrated_apps_restricted(**kwargs):
    tenant = kwargs["tenant"]
    approval = kwargs.get("approval")
    mode = (kwargs.get("mode") or "report-only").strip().lower()

    def _cur(ap: dict):
        return (ap.get("defaultUserRolePermissions") or {}).get("allowedToCreateSecurityGroups", None)

    def _payload_from(ap: dict) -> dict:
        durp = (ap.get("defaultUserRolePermissions") or {}).copy()
        durp["allowedToCreateSecurityGroups"] = False
        return {"defaultUserRolePermissions": durp}

    return _enforce_authz_bool(
        tenant=tenant,
        control_id="IntegratedAppsRestricted",
        approval=approval,
        mode=mode,
        get_current_value_fn=_cur,
        desired_payload=None,
        desired_value=False,
        build_payload_fn=_payload_from,
    )

# =========================
# ThirdPartyAppsRestricted
# =========================
def _third_party_apps_restricted(**kwargs):
    tenant = kwargs["tenant"]
    approval = kwargs.get("approval")
    mode = (kwargs.get("mode") or "report-only").strip().lower()

    def _cur(ap: dict):
        return ap.get("allowUserConsentForRiskyApps", None)

    payload = {"allowUserConsentForRiskyApps": False}

    return _enforce_authz_bool(
        tenant=tenant,
        control_id="ThirdPartyAppsRestricted",
        approval=approval,
        mode=mode,
        get_current_value_fn=_cur,
        desired_payload=payload,
        desired_value=False,
    )


# Register (batch)
register("AdminOwnedAppsRestricted", _admin_owned_apps_restricted)
register("IntegratedAppsRestricted", _integrated_apps_restricted)
register("ThirdPartyAppsRestricted", _third_party_apps_restricted)
