# engine/enforcement/sspr_enforcer.py
from __future__ import annotations

from typing import Tuple

from engine.enforcement.registry import register
from engine.enforcement.graph_singleton import graph_get_json, graph_patch_json, verify_with_retries


def _self_service_password_reset(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    """
    Control: SelfServicePasswordReset
    Endpoint: /v1.0/policies/authenticationMethodsPolicy
    Property: isSelfServicePasswordResetEnabled
    """
    # NOTE: In this tenant/API surface, authenticationMethodsPolicy does not expose
    # isSelfServicePasswordResetEnabled as a readable property (cannot verify).
    # Therefore we do NOT attempt enforcement. Be explicit and conservative.
    url = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
    mode = (mode or "report-only").strip().lower()

    details = {
        "url": url,
        "before": {control_id: None},
        "desired": {control_id: True},
        "note": "No supported app-only API signal found that exposes/verifies SSPR enablement via this endpoint.",
        "remediation": "Configure SSPR in Entra admin center (Users > Password reset) and ensure your detector is anchored to a verifiable API signal before enforcing.",
    }

    if mode == "enforce":
        return (
            "NOT_EVALUATED",
            "UNSUPPORTED_API",
            "Cannot enforce SelfServicePasswordReset: Graph does not expose a verifiable SSPR property on authenticationMethodsPolicy in this environment.",
            details,
            424,
        )

    return (
        "NOT_EVALUATED",
        "MISSING_SIGNAL",
        "Report-only: no verifiable app-only API signal available for SelfServicePasswordReset.",
        details,
        200,
    )

    evidence_key = control_id

    details = {
        "url": url,
        "before": {evidence_key: before_val},
        "desired": {evidence_key: True},
    }

    # Report-only: never write
    if mode != "enforce":
        if before_val is True:
            return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: already enabled", details, 200)
        if before_val is False:
            return ("DRIFTED", "REPORT_ONLY_EVALUATED", "Report-only: drift detected", details, 200)
        return ("NOT_EVALUATED", "INSUFFICIENT_SIGNAL", "Report-only: value not returned by API", details, 200)

    # Enforce: idempotent
    if before_val is True:
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Already in desired state; no changes applied", details, 200)

    desired_payload = {"isSelfServicePasswordResetEnabled": True}
    a_status, a_body, a_text = graph_patch_json(url, headers=headers, payload=desired_payload, timeout=30)
    details["apply"] = {
        "status": a_status,
        "responseText": (a_text or "")[:2000] if a_text else None,
        "applied": desired_payload,
    }

    if a_status >= 400:
        return (
            "ERROR",
            "ENFORCER_ERROR",
            f"Graph PATCH authenticationMethodsPolicy failed (HTTP {a_status})",
            details,
            a_status,
        )

    def _get():
        return graph_get_json(url, headers=headers, timeout=30)

    def _is_desired(body: dict) -> bool:
        return (body or {}).get("isSelfServicePasswordResetEnabled", None) is True

    v_status, v_body, v_text, attempt_used = verify_with_retries(_get, _is_desired, attempts=5, delay_seconds=2.0)
    after_val = (v_body or {}).get("isSelfServicePasswordResetEnabled", None)

    details["verify"] = {"status": v_status, "attempt": attempt_used, "responseText": (v_text or "")[:2000] if v_text else None}
    details["after"] = {evidence_key: after_val}

    if after_val is True:
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforcer executed; post-state verified", details, 200)
    if after_val is False:
        return ("DRIFTED", "ENFORCER_EXECUTED", "Enforcer executed; drift remains after verify", details, 200)
    return ("NOT_EVALUATED", "ENFORCER_EXECUTED", "Enforcer executed; post-state unclear", details, 200)


register("SelfServicePasswordReset", _self_service_password_reset)
