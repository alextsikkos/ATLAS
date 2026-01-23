# engine/tier3/gates.py

from __future__ import annotations
from typing import Any


def attach_reason(event: dict, code: str, detail: str | None = None) -> dict:
    """
    Add stable reason fields for reporting.
    - reasonCode: machine-readable
    - reasonDetail: human-readable
    Keeps existing 'reason' field untouched if already present.
    """
    event["reasonCode"] = code
    if detail is not None:
        event["reasonDetail"] = detail
        event.setdefault("reason", detail)
    return event


def return_not_evaluated(
    *,
    write_audit_event,  # function passed in from main.py
    tenant_name: str,
    control_id: str,
    control: dict,
    mode: str,
    approval: dict | None,
    reason: str,
    details: dict | None = None,
) -> str:
    # Allow caller to override reasonCode/reasonDetail via details for non-tier3 missing-signal cases
    d = details or {}
    code = d.get("reasonCode") or "TIER3_BLOCKED"
    detail = d.get("reasonDetail") or reason

    audit_path = write_audit_event(
        tenant_name,
        attach_reason(
            {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "tier3_gate_blocked",
                "state": "NOT_EVALUATED",
                "displayName": control.get("name", control_id),
                "approved": bool(approval),
                "mode": mode,
                "status": 409,
                "reason": reason,
                "details": d,
            },
            code,
            detail,
        ),
    )


    detail_suffix = ""
    if isinstance(details, dict):
        if details.get("missing"):
            detail_suffix = f" | missing={details['missing']}"
        elif details:
            detail_suffix = f" | details={details}"

    print(f"TIER3_BLOCK: {control_id} | state=NOT_EVALUATED | {reason}{detail_suffix}")

    print(f"Audit saved: {audit_path}")
    return audit_path


def safety_block_if_no_break_glass(
    control_id: str,
    mode: str,
    approval: dict | None,
    tenant: dict,
) -> tuple[bool, dict]:

    """
    Safety gate for lockout-capable controls.
    Returns (blocked, details).
    """
    if mode != "enforce":
        return False, {}

    # Break glass group id is required to even consider enforcement
    break_glass_group_id = (tenant or {}).get("break_glass_group_id")
    if not break_glass_group_id:
        return True, {
            "reason": "break_glass_group_id missing from tenant configuration",
            "requiredTenantField": "break_glass_group_id",
            "controlId": control_id,
        }

    # Explicit approval acknowledgement required
    if not approval or approval.get("acknowledgeLockoutRisk") is not True:
        return True, {
            "reason": "approval missing acknowledgeLockoutRisk=true for enforce on lockout-capable control",
            "requiredApprovalField": "acknowledgeLockoutRisk",
            "controlId": control_id,
        }

    return False, {"breakGlassGroupId": break_glass_group_id}


def tier3_requires_acknowledgements(control: dict) -> bool:
    # You already use tags like onboardingRequired / canCauseLockout in registry.
    # Keep it conservative: tier==3 implies onboarding ack gate.
    return int(control.get("tier", 0) or 0) == 3


def missing_tier3_ack_fields(approval: dict | None) -> list[str]:
    """
    Keep this aligned with your current expected ack fields.

    Backwards-compatible:
    - Accepts top-level keys (current format)
    - Also accepts nested approval["acknowledgements"][key] (common alternate format)
    """
    missing: list[str] = []

    acks = {}
    if isinstance(approval, dict):
        acks = approval.get("acknowledgements") or {}
        if not isinstance(acks, dict):
            acks = {}

    def _ack_true(key: str) -> bool:
        if not isinstance(approval, dict):
            return False
        if approval.get(key) is True:
            return True
        if acks.get(key) is True:
            return True
        return False

    if not _ack_true("acknowledgeBusinessImpact"):
        missing.append("acknowledgeBusinessImpact:true")
    if not _ack_true("onboardingReviewed"):
        missing.append("onboardingReviewed:true")

    return missing
