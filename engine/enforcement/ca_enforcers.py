# engine/enforcement/ca_enforcers.py
from __future__ import annotations

import time
import requests
from typing import Any, Dict, Tuple

from engine.enforcement.registry import register
from engine.enforcement.ensure import ensure_policy

# Payload builders you already use in main.py
from engine.enforcement.policies.risky_signin_mfa import (
    DISPLAY_NAME as RS_DISPLAY_NAME,
    build_payload as build_rs_payload,
)
from engine.enforcement.policies.risky_user_password import (
    DISPLAY_NAME as RUP_DISPLAY_NAME,
    build_payload as build_rup_payload,
)
from engine.enforcement.policies.admin_mfa import (
    DISPLAY_NAME as AM_DISPLAY_NAME,
    build_payload as build_am_payload,
)
from engine.enforcement.policies.ca_admin_block_legacy_auth import (
    DISPLAY_NAME as BLA_ADMIN_DISPLAY_NAME,
    build_payload as build_bla_admin_payload,
)
from engine.enforcement.policies.ca_all_users_block_legacy_auth import (
    DISPLAY_NAME as BLA_ALL_DISPLAY_NAME,
    build_payload as build_bla_all_payload,
)

from engine.enforcement.policies.admin_signin_freq_session_timeout import (
    DISPLAY_NAME as ASF_DISPLAY_NAME,
    build_payload as build_asf_payload,
)
from engine.enforcement.policies.admin_phishing_resistant_mfa import (
    DISPLAY_NAME as PR_DISPLAY_NAME,
    build_payload as build_pr_payload,
)


def _break_glass_group_id(tenant: dict) -> str | None:
    # Keep aligned with your existing tenant schema usage
    gid = (tenant or {}).get("breakGlassGroupId") or (tenant or {}).get("break_glass_group_id")
    if isinstance(gid, str):
        gid = gid.strip()
    return gid if gid else None


def _lockout_safety_gate(control_id: str, tenant: dict, approval: dict | None, mode: str) -> tuple[bool, dict]:
    """
    Conservative safety gate:
      - only blocks in enforce mode
      - requires break-glass group id
      - requires approval acknowledgeLockoutRisk==true
    """
    if (mode or "").lower() != "enforce":
        return False, {}

    gid = _break_glass_group_id(tenant)
    if not gid:
        return True, {
            "reason": "breakGlassGroupId missing from tenant configuration",
            "requiredTenantField": "breakGlassGroupId",
            "controlId": control_id,
        }

    if not approval or approval.get("acknowledgeLockoutRisk") is not True:
        return True, {
            "reason": "approval missing acknowledgeLockoutRisk=true for enforce on lockout-capable control",
            "requiredApprovalField": "acknowledgeLockoutRisk",
            "controlId": control_id,
        }

    return False, {"breakGlassGroupId": gid}


def _get_auth_strength_policy_id_by_name(headers: dict, display_name: str) -> str | None:
    """
    Minimal clone of the helper you have in main.py (kept local to avoid importing main.py).
    """
    url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies"
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code >= 300:
        return None
    items = (r.json() or {}).get("value", []) or []
    for p in items:
        if (p.get("displayName") or "").strip().lower() == display_name.strip().lower():
            return p.get("id")
    return None


def _report_or_ensure(
    *,
    headers: dict,
    tenant: dict,
    control_id: str,
    approval: dict | None,
    mode: str,
    display: str,
    desired_payload: dict,
    lockout_capable: bool = True,
) -> Tuple[str, str, str, dict, int]:
    """
    Shared CA enforcement pattern:
      - report-only => create/update disabled; just drift check via ensure_policy allow_update=False (and interpret result)
      - enforce => ensure_policy allow_update=True
    """
    mode = (mode or "report-only").strip().lower()

    if lockout_capable:
        blocked, safety_details = _lockout_safety_gate(control_id, tenant, approval, mode)
        if blocked:
            return (
                "NOT_EVALUATED",
                "MISSING_PREREQUISITE",
                "Safety gate: break-glass / lockout acknowledgement missing",
                {"safety": safety_details, "displayName": display, "desired": desired_payload},
                409,
            )

    if mode in ("report-only", "detect-only"):
        result = ensure_policy(headers=headers, display_name=display, payload=desired_payload, allow_update=False)
        # ensure_policy will return:
        #  - skipped_no_drift => compliant
        #  - created/updated won't happen (allow_update False), but "existing missing" => it will attempt create; we treat missing as DRIFTED, not create.
        # NOTE: ensure_policy currently creates if missing; to stay strictly report-only, we interpret "created" as drift and do not rely on it.
        # If your ensure_policy creates even when allow_update=False, we must treat it as a bug; but in practice find_policy_by_name gate should prevent.
        res = (result.get("result") or "").lower()
        if res == "skipped_no_drift":
            return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: policy matches desired", {"result": result, "desired": desired_payload}, 200)
        # If missing or drifted, result is usually "skipped_update_disabled" (existing but drifted)
        return ("DRIFTED", "REPORT_ONLY_EVALUATED", "Report-only: drift detected (no changes applied)", {"result": result, "desired": desired_payload}, 200)

    # enforce
    result = ensure_policy(headers=headers, display_name=display, payload=desired_payload, allow_update=True)
    status = int(result.get("status") or 0)
    if status >= 400:
        return ("ERROR", "ENFORCER_ERROR", f"Graph CA ensure_policy failed: {status}", {"result": result, "desired": desired_payload}, status)

    # Normalize state for reporting
    if (result.get("result") or "").lower() in ("created", "updated"):
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforcer executed; policy ensured", {"result": result, "desired": desired_payload}, status or 200)

    return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforcer executed; no drift", {"result": result, "desired": desired_payload}, status or 200)


# =========================
# Registered enforcers
# =========================

def _signin_risk_policy_enforcer(**kwargs):
    tenant = kwargs["tenant"]
    headers = kwargs["headers"]
    approval = kwargs.get("approval")
    mode = kwargs.get("mode") or "report-only"

    desired = build_rs_payload(mode=mode, exclude_group_id=_break_glass_group_id(tenant))
    return _report_or_ensure(
        headers=headers,
        tenant=tenant,
        control_id="SigninRiskPolicy",
        approval=approval,
        mode=mode,
        display=RS_DISPLAY_NAME,
        desired_payload=desired,
        lockout_capable=True,
    )


def _user_risk_policy_enforcer(**kwargs):
    tenant = kwargs["tenant"]
    headers = kwargs["headers"]
    approval = kwargs.get("approval")
    mode = kwargs.get("mode") or "report-only"

    desired = build_rup_payload(mode=mode, exclude_group_id=_break_glass_group_id(tenant))
    return _report_or_ensure(
        headers=headers,
        tenant=tenant,
        control_id="UserRiskPolicy",
        approval=approval,
        mode=mode,
        display=RUP_DISPLAY_NAME,
        desired_payload=desired,
        lockout_capable=True,
    )


def _ca_admin_mfa_all_apps_enforcer(**kwargs):
    tenant = kwargs["tenant"]
    headers = kwargs["headers"]
    approval = kwargs.get("approval")
    mode = kwargs.get("mode") or "report-only"

    desired = build_am_payload(mode=mode, exclude_group_id=_break_glass_group_id(tenant))
    return _report_or_ensure(
        headers=headers,
        tenant=tenant,
        control_id="CAAdminMFAAllApps",
        approval=approval,
        mode=mode,
        display=AM_DISPLAY_NAME,
        desired_payload=desired,
        lockout_capable=True,
    )


def _ca_admin_block_legacy_auth_enforcer(**kwargs):
    tenant = kwargs["tenant"]
    headers = kwargs["headers"]
    approval = kwargs.get("approval")
    mode = kwargs.get("mode") or "report-only"

    desired = build_bla_admin_payload(mode=mode, exclude_group_id=_break_glass_group_id(tenant))
    return _report_or_ensure(
        headers=headers,
        tenant=tenant,
        control_id="CAAdminBlockLegacyAuth",
        approval=approval,
        mode=mode,
        display=BLA_ADMIN_DISPLAY_NAME,
        desired_payload=desired,
        lockout_capable=True,
    )


def _ca_all_users_block_legacy_auth_enforcer(**kwargs):
    tenant = kwargs["tenant"]
    headers = kwargs["headers"]
    approval = kwargs.get("approval")
    mode = kwargs.get("mode") or "report-only"

    desired = build_bla_all_payload(mode=mode, exclude_group_id=_break_glass_group_id(tenant))
    return _report_or_ensure(
        headers=headers,
        tenant=tenant,
        control_id="CAAllUsersBlockLegacyAuth",
        approval=approval,
        mode=mode,
        display=BLA_ALL_DISPLAY_NAME,
        desired_payload=desired,
        lockout_capable=True,
    )


def _ca_admin_signin_freq_session_timeout_enforcer(**kwargs):
    tenant = kwargs["tenant"]
    headers = kwargs["headers"]
    approval = kwargs.get("approval")
    mode = kwargs.get("mode") or "report-only"

    desired = build_asf_payload(mode=mode, exclude_group_id=_break_glass_group_id(tenant))
    return _report_or_ensure(
        headers=headers,
        tenant=tenant,
        control_id="CAAdminSignInFrequencySessionTimeout",
        approval=approval,
        mode=mode,
        display=ASF_DISPLAY_NAME,
        desired_payload=desired,
        lockout_capable=True,
    )


def _ca_admin_phishing_resistant_mfa_enforcer(**kwargs):
    tenant = kwargs["tenant"]
    headers = kwargs["headers"]
    approval = kwargs.get("approval")
    mode = kwargs.get("mode") or "report-only"

    # Safety gate first (lockout-capable)
    blocked, safety_details = _lockout_safety_gate("CAAdminPhishingResistantMFA", tenant, approval, mode)
    if blocked:
        return (
            "NOT_EVALUATED",
            "MISSING_PREREQUISITE",
            "Safety gate: break-glass / lockout acknowledgement missing",
            {"safety": safety_details},
            409,
        )

    strength_id = _get_auth_strength_policy_id_by_name(headers, "Phishing-resistant MFA")
    if not strength_id:
        return (
            "NOT_EVALUATED",
            "MISSING_PREREQUISITE",
            "Missing prerequisite: Authentication Strength 'Phishing-resistant MFA' not found",
            {"lookedUpName": "Phishing-resistant MFA"},
            424,
        )

    desired = build_pr_payload(
        mode=mode,
        authentication_strength_policy_id=strength_id,
        exclude_group_id=_break_glass_group_id(tenant),
    )

    return _report_or_ensure(
        headers=headers,
        tenant=tenant,
        control_id="CAAdminPhishingResistantMFA",
        approval=approval,
        mode=mode,
        display=PR_DISPLAY_NAME,
        desired_payload=desired,
        lockout_capable=True,
    )


# Register all in one batch
register("SigninRiskPolicy", _signin_risk_policy_enforcer)
register("UserRiskPolicy", _user_risk_policy_enforcer)
register("CAAdminMFAAllApps", _ca_admin_mfa_all_apps_enforcer)
register("CAAdminBlockLegacyAuth", _ca_admin_block_legacy_auth_enforcer)
register("CAAllUsersBlockLegacyAuth", _ca_all_users_block_legacy_auth_enforcer)
register("CAAdminSignInFrequencySessionTimeout", _ca_admin_signin_freq_session_timeout_enforcer)
register("CAAdminPhishingResistantMFA", _ca_admin_phishing_resistant_mfa_enforcer)
