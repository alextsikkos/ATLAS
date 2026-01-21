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

    # PATCH succeeded but the service did not persist the desired configuration.
    # Treat as a policy constraint / unsupported mode rather than a runtime error.
    return (
        "NOT_EVALUATED",
        "UNSUPPORTED_MODE",
        "PATCH succeeded but desired TAP settings did not persist (likely constrained by includeTargets/tenant rules).",
        details,
        424,
    )


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

    # PATCH succeeded but the service did not persist the desired configuration.
    # Treat as a policy constraint (tenant rules/targeting) rather than a runtime error.
    details["constraint"] = {
        "note": "PATCH returned success but desired fields did not persist after verify.",
        "likelyCause": "Tenant rules / includeTargets constraints / service-side normalization.",
    }
    return (
        "NOT_EVALUATED",
        "POLICY_CONSTRAINT",
        "Service accepted PATCH but did not persist desired TAP settings (likely constrained by targeting/tenant rules).",
        details,
        424,
    )


def _temporary_access_pass_lifetime_hardened(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    desired_patch = {
        "defaultLifetimeInMinutes": 60,
    }
    verify_fields = {
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
def _temporary_access_pass_usable_once(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    # Preflight: if includeTargets is all_users, do NOT attempt.
    # Your tenant shows includeTargets = all_users. :contentReference[oaicite:3]{index=3}
    url = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass"
    g_status, g_body, g_text = graph_get_json(url, headers=headers, timeout=30)
    if g_status >= 400 or not isinstance(g_body, dict):
        return (
            "NOT_EVALUATED",
            "AUTH_FORBIDDEN" if g_status == 403 else "MISSING_SIGNAL",
            f"Graph GET TAP configuration failed (HTTP {g_status})",
            {"url": url, "status": g_status, "responseText": (g_text or "")[:2000]},
            g_status,
        )

    include_targets = (g_body or {}).get("includeTargets", []) or []
    includes_all_users = any((t or {}).get("id") == "all_users" for t in include_targets)

    if includes_all_users:
        details = {
            "url": url,
            "includeTargets": include_targets,
            "note": "Refusing to enforce isUsableOnce when TAP targets all users; this commonly fails to persist and is high risk.",
            "remediation": "Scope TAP to a piloted group, then re-run with approval to enforce usable-once.",
        }
        if (mode or "").strip().lower() == "enforce":
            return ("NOT_EVALUATED", "POLICY_CONSTRAINT", "TAP targets all users; usable-once enforcement is blocked.", details, 409)
        return ("NOT_EVALUATED", "INSUFFICIENT_SIGNAL", "Report-only: TAP targets all users; usable-once not enforced.", details, 200)

    # If not all_users, attempt to enforce isUsableOnce
    desired_patch = {"isUsableOnce": True}
    verify_fields = {"isUsableOnce": True}

    # reuse the generic helper (it will now return POLICY_CONSTRAINT if it still doesn't persist)
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
def _software_oath_enabled(
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
        method_id="softwareOath",
        desired_state="enabled",
        control_id=control_id,
        mode=mode,
    )


def _hardware_oath_enabled(
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
        method_id="hardwareOath",
        desired_state="enabled",
        control_id=control_id,
        mode=mode,
    )


def _x509_certificate_disabled(
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
        method_id="x509Certificate",
        desired_state="disabled",
        control_id=control_id,
        mode=mode,
    )

register("AuthMethodsTemporaryAccessPassHardened", _temporary_access_pass_lifetime_hardened)
register("AuthMethodsTemporaryAccessPassUsableOnce", _temporary_access_pass_usable_once)
register("AuthMethodsSoftwareOathEnabled", _software_oath_enabled)
register("AuthMethodsHardwareOathEnabled", _hardware_oath_enabled)
register("AuthMethodsX509CertificateDisabled", _x509_certificate_disabled)

register("AuthMethodsMicrosoftAuthenticatorEnabled", _microsoft_authenticator_enabled)
register("AuthMethodsFido2Enabled", _fido2_enabled)
register("AuthMethodsSmsDisabled", _sms_disabled)
register("AuthMethodsVoiceDisabled", _voice_disabled)

print("[INFO] Loaded auth_methods_policy_enforcers; handlers registered")
