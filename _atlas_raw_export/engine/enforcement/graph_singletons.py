# engine/enforcement/graph_singletons.py
from __future__ import annotations

from typing import Any, Dict, Tuple

from engine.enforcement.registry import register

# Uses your existing helper (already proven in your environment)
from engine.enforcement.graph_singleton import graph_get_json, graph_put_json, verify_with_retries


def _admin_consent_workflow_enabled(
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    """
    Control: AdminConsentWorkflowEnabled
    Endpoint: /v1.0/policies/adminConsentRequestPolicy
    Method: PUT (preserve required fields + set isEnabled=True)
    """
    url = "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"

    status, body, text = graph_get_json(url, headers=headers, timeout=30)
    if status >= 400:
        return (
            "NOT_EVALUATED",
            "AUTH_FORBIDDEN" if status == 403 else "MISSING_SIGNAL",
            f"Graph GET failed: {status}",
            {"url": url, "errorText": (text or "")[:500]},
            status,
        )

    before_enabled = body.get("isEnabled", None)

    details = {
        "url": url,
        "before": {"isEnabled": before_enabled},
        "desired": {"isEnabled": True},
    }

    # report-only: no write
    if mode == "report-only":
        if before_enabled is True:
            return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: already enabled", details, 200)
        if before_enabled is False:
            return ("DRIFTED", "REPORT_ONLY_EVALUATED", "Report-only: drift detected", details, 200)
        return ("NOT_EVALUATED", "REPORT_ONLY_EVALUATED", "Report-only: insufficient signal", details, 200)

    # enforce: PUT full payload (preserve required fields)
    required_fields = ["notifyReviewers", "remindersEnabled", "requestDurationInDays", "reviewers"]
    missing = [k for k in required_fields if k not in body]
    if missing:
        details["missingRequiredFields"] = missing
        return (
            "NOT_EVALUATED",
            "INSUFFICIENT_SIGNAL",
            f"Refusing to enforce: missing required fields from GET: {missing}",
            details,
            200,
        )

    put_payload = {
        "isEnabled": True,
        "notifyReviewers": body["notifyReviewers"],
        "remindersEnabled": body["remindersEnabled"],
        "requestDurationInDays": body["requestDurationInDays"],
        "reviewers": body["reviewers"],
    }

    p_status, p_body, p_text = graph_put_json(url, headers=headers, payload=put_payload, timeout=30)
    details["apply"] = {"status": p_status, "response": (p_text or "")[:500] if p_text else None}

    if p_status >= 400:
        return ("ERROR", "ENFORCER_ERROR", f"Graph PUT failed: {p_status}", details, p_status)

    def _get():
        return graph_get_json(url, headers=headers, timeout=30)

    def _is_desired(b: dict) -> bool:
        return b.get("isEnabled", None) is True

    v_status, v_body, v_text, attempt_used = verify_with_retries(_get, _is_desired, attempts=5, delay_seconds=2.0)
    after_enabled = (v_body or {}).get("isEnabled", None)

    details["verify"] = {"status": v_status, "attempt": attempt_used, "response": (v_text or "")[:500]}
    details["after"] = {"isEnabled": after_enabled}

    if after_enabled is True:
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforcer executed; post-state verified", details, 200)
    if after_enabled is False:
        return ("DRIFTED", "ENFORCER_EXECUTED", "Enforcer executed; drift remains after verify", details, 200)
    return ("NOT_EVALUATED", "ENFORCER_EXECUTED", "Enforcer executed; post-state unclear", details, 200)


# Register enforcers here (batch-friendly)
register("AdminConsentWorkflowEnabled", _admin_consent_workflow_enabled)
