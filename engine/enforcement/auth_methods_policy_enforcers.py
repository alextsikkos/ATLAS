# engine/enforcement/auth_methods_policy_enforcers.py
from __future__ import annotations

from typing import Tuple

from engine.enforcement.registry import register
from engine.enforcement.graph_singleton import graph_get_json, graph_patch_json, verify_with_retries


def _enforce_auth_method_state(
    *,
    headers: dict,
    method_id: str,
    desired_state: str,
    control_id: str,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    """
    Generic enforcer for:
      /v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/{method_id}

    Enforces/verifies the top-level "state" property: "enabled" | "disabled".
    """
    url = (
        "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/"
        f"authenticationMethodConfigurations/{method_id}"
    )
    mode_eff = (mode or "report-only").strip().lower()

    # 1) GET before
    g_status, g_body, g_text = graph_get_json(url, headers=headers, timeout=30)
    if g_status >= 400 or not isinstance(g_body, dict):
        return (
            "NOT_EVALUATED",
            "AUTH_FORBIDDEN" if g_status == 403 else "MISSING_SIGNAL",
            f"Graph GET auth method configuration failed (HTTP {g_status})",
            {"url": url, "status": g_status, "responseText": (g_text or "")[:2000]},
            g_status,
        )

    before_state = (g_body or {}).get("state", None)

    details = {
        "url": url,
        "before": {control_id: before_state},
        "desired": {control_id: desired_state},
    }

    # Report-only evaluation
    if mode_eff == "report-only":
        if before_state == desired_state:
            return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: already compliant (no changes applied).", details, 200)
        return ("DRIFTED", "REPORT_ONLY_EVALUATED", "Report-only: drift detected (no changes applied).", details, 200)

    if mode_eff != "enforce":
        return ("NOT_EVALUATED", "UNSUPPORTED_MODE", f"Unsupported mode for enforcer: {mode}", details, 200)

    # 2) Enforce (idempotent)
    if before_state == desired_state:
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforce: already compliant (no change needed).", details, 200)

    payload = {"state": desired_state}
    a_status, a_body, a_text = graph_patch_json(url, headers=headers, payload=payload, timeout=30)
    details["apply"] = {
        "status": a_status,
        "applied": payload,
        "responseText": (a_text or "")[:2000] if a_text else None,
    }

    if a_status >= 400:
        return ("ERROR", "ENFORCER_ERROR", f"Graph PATCH auth method configuration failed (HTTP {a_status})", details, a_status)

    # 3) Verify
    def _get():
        return graph_get_json(url, headers=headers, timeout=30)

    def _is_desired(body: dict) -> bool:
        return (body or {}).get("state", None) == desired_state

    v_status, v_body, v_text, attempt_used = verify_with_retries(_get, _is_desired, attempts=5, delay_seconds=2.0)
    after_state = (v_body or {}).get("state", None)

    details["verify"] = {
        "status": v_status,
        "attempt": attempt_used,
        "responseText": (v_text or "")[:2000] if v_text else None,
    }
    details["after"] = {control_id: after_state}

    if after_state == desired_state:
        return ("UPDATED", "ENFORCER_EXECUTED", "Enforce: applied change and verified.", details, 200)

    return ("ERROR", "ENFORCER_ERROR", "Enforce: attempted but could not verify desired state.", details, 200)

def _enforce_auth_method_config(
    *,
    headers: dict,
    method_id: str,
    desired_patch: dict,
    verify_fields: dict,
    control_id: str,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    url = (
        "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/"
        f"authenticationMethodConfigurations/{method_id}"
    )
    mode_eff = (mode or "report-only").strip().lower()

    # 1) GET before
    g_status, g_body, g_text = graph_get_json(url, headers=headers, timeout=30)
    if g_status >= 400 or not isinstance(g_body, dict):
        return (
            "NOT_EVALUATED",
            "AUTH_FORBIDDEN" if g_status == 403 else "MISSING_SIGNAL",
            f"Graph GET auth method configuration failed (HTTP {g_status})",
            {"url": url, "status": g_status, "responseText": (g_text or "")[:2000]},
            g_status,
        )

    before = {k: (g_body or {}).get(k, None) for k in verify_fields.keys()}
    desired = verify_fields.copy()

    details = {"url": url, "before": {control_id: before}, "desired": {control_id: desired}}

    # Report-only evaluation
    if mode_eff == "report-only":
        if all(before.get(k) == v for k, v in desired.items()):
            return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: already compliant (no changes applied).", details, 200)
        return ("DRIFTED", "REPORT_ONLY_EVALUATED", "Report-only: drift detected (no changes applied).", details, 200)

    if mode_eff != "enforce":
        return ("NOT_EVALUATED", "UNSUPPORTED_MODE", f"Unsupported mode for enforcer: {mode}", details, 200)

    # Enforce idempotently
    if all(before.get(k) == v for k, v in desired.items()):
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforce: already compliant (no change needed).", details, 200)

    # 2) PATCH
    a_status, a_body, a_text = graph_patch_json(url, headers=headers, payload=desired_patch, timeout=30)
    details["apply"] = {
        "status": a_status,
        "applied": desired_patch,
        "responseText": (a_text or "")[:2000] if a_text else None,
    }
    if a_status >= 400:
        return ("ERROR", "ENFORCER_ERROR", f"Graph PATCH auth method configuration failed (HTTP {a_status})", details, a_status)

    # 3) VERIFY
    def _get():
        return graph_get_json(url, headers=headers, timeout=30)

    def _is_desired(body: dict) -> bool:
        if not isinstance(body, dict):
            return False
        return all((body or {}).get(k, None) == v for k, v in desired.items())

    v_status, v_body, v_text, attempt_used = verify_with_retries(_get, _is_desired, attempts=5, delay_seconds=2.0)
    after = {k: (v_body or {}).get(k, None) for k in verify_fields.keys()}

    details["verify"] = {
        "status": v_status,
        "attempt": attempt_used,
        "responseText": (v_text or "")[:2000] if v_text else None,
    }
    details["after"] = {control_id: after}

    if all(after.get(k) == v for k, v in desired.items()):
        return ("UPDATED", "ENFORCER_EXECUTED", "Enforce: applied change and verified.", details, 200)

    return ("ERROR", "ENFORCER_ERROR", "Enforce: attempted but could not verify desired state.", details, 200)
def _temporary_access_pass_hardened(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    # Conservative defaults that harden security but shouldn’t break sane onboarding:
    # - TAP enabled (if you don’t want ATLAS enabling it, set desired_patch["state"]="enabled" -> remove, and only harden if enabled)
    # - One-time use
    # - Short default lifetime
    desired_patch = {
        "state": "enabled",
        "isUsableOnce": True,
        "defaultLifetimeInMinutes": 60,
    }

    verify_fields = {
        "state": "enabled",
        "isUsableOnce": True,
        "defaultLifetimeInMinutes": 60,
    }

    return _enforce_auth_method_config(
        headers=headers,
        method_id="temporaryAccessPass",
        desired_patch=desired_patch,
        verify_fields=verify_fields,
        control_id=control_id,
        mode=mode,
    )

def _microsoft_authenticator_enabled(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    return _enforce_auth_method_state(
        headers=headers,
        method_id="microsoftAuthenticator",
        desired_state="enabled",
        control_id=control_id,
        mode=mode,
    )
def _fido2_enabled(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    return _enforce_auth_method_state(
        headers=headers,
        method_id="fido2",
        desired_state="enabled",
        control_id=control_id,
        mode=mode,
    )
def _sms_disabled(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    return _enforce_auth_method_state(
        headers=headers,
        method_id="sms",
        desired_state="disabled",
        control_id=control_id,
        mode=mode,
    )


def _voice_disabled(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    return _enforce_auth_method_state(
        headers=headers,
        method_id="voice",
        desired_state="disabled",
        control_id=control_id,
        mode=mode,
    )

register("AuthMethodsTemporaryAccessPassHardened", _temporary_access_pass_hardened)
register("AuthMethodsMicrosoftAuthenticatorEnabled", _microsoft_authenticator_enabled)
register("AuthMethodsFido2Enabled", _fido2_enabled)
register("AuthMethodsSmsDisabled", _sms_disabled)
register("AuthMethodsVoiceDisabled", _voice_disabled)

print("[INFO] Loaded auth_methods_policy_enforcers; handlers registered")
