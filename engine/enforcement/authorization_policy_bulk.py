from __future__ import annotations

import time
import requests
from typing import Any, Dict, Tuple

from engine.enforcement.registry import register
from engine.approvals.reader import is_control_approved


AUTHZ_URL = "https://graph.microsoft.com/beta/policies/authorizationPolicy"


# controlId -> (json_path, desired_value)
CONTROL_FIELD_MAP = {
    # User consent / apps
    "DisableUserConsentToApps": ("permissionGrantPolicyIdsAssignedToDefaultUserRole", []),


    "ThirdPartyAppsRestricted": ("allowUserConsentForRiskyApps", False),

    # Guest / external
    "GuestInvitesRestrictedToAdminsAndGuestInviters": ("allowInvitesFrom", "adminsAndGuestInviters"),
    "EmailVerifiedUsersCannotJoinOrganization": ("allowEmailVerifiedUsersToJoinOrganization", False),
    "EmailBasedSubscriptionsDisabled": ("allowEmailBasedSubscriptions", False),

    # Legacy / PowerShell
    "BlockMsolPowerShellEnabled": ("blockMsolPowerShell", True),

    # Default user role permissions
    "DefaultUserRoleAppsCreationDisabled": ("defaultUserRolePermissions.allowedToCreateApps", False),
    "DefaultUserRoleSecurityGroupsCreationDisabled": ("defaultUserRolePermissions.allowedToCreateSecurityGroups", False),
    "DefaultUserRoleTenantCreationDisabled": ("defaultUserRolePermissions.allowedToCreateTenants", False),
    "DefaultUserRoleReadOtherUsersDisabled": ("defaultUserRolePermissions.allowedToReadOtherUsers", False),
    "DefaultUserRoleReadBitlockerKeysForOwnedDeviceDisabled": ("defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice", False),

    # App ownership
    "AdminOwnedAppsRestricted": ("defaultUserRolePermissions.allowedToCreateApps", False),
    "IntegratedAppsRestricted": ("defaultUserRolePermissions.allowedToCreateSecurityGroups", False),
}


def _set_dot_path(obj: dict, path: str, value):
    cur = obj
    parts = path.split(".")
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _get_path(obj: dict, path: str):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _set_path(obj: dict, path: str, value):
    cur = obj
    parts = path.split(".")
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _graph(method: str, headers: dict, url: str, json_body: dict | None = None, timeout_s: int = 30):
    if method == "GET":
        r = requests.get(url, headers=headers, timeout=timeout_s)
    elif method == "PATCH":
        r = requests.patch(url, headers=headers, json=json_body, timeout=timeout_s)
    else:
        raise ValueError(f"Unsupported method: {method}")
    return r


def _run_bulk_once(tenant: dict, tenant_name: str, headers: dict) -> dict:
    """
    Runs at most once per tenant per run.
    Stores base (GET-before) evidence in tenant["_authz_bulk"].
    Per-control PATCH/verify happens in the per-control enforcer (isolated payloads).
    """
    ctx = tenant.setdefault("_authz_bulk", {})
    if ctx.get("ran"):
        return ctx

    ctx["ran"] = True
    ctx["results"] = {}  # controlId -> tuple(state, reasonCode, reasonDetail, details, status)

    matched = tenant.get("_atlas_matched_controls") or []
    present_ids = {
        ((c.get("atlasControlId") or c.get("controlId") or "")).strip()
        for c in matched
        if isinstance(c, dict)
    }
    # We are only invoked for authz-policy controls; don’t depend on matched-controls metadata shape.
    target_ids = list(CONTROL_FIELD_MAP.keys())
    if not target_ids:
        return ctx


    # Determine which controls are approved for enforce (file-based approvals)
    approved_for_enforce: list[str] = []
    approval_payloads: dict[str, dict] = {}

    for cid in target_ids:
        approved, _reason, payload = is_control_approved(tenant_name, cid)
        if isinstance(payload, dict):
            approval_payloads[cid] = payload
        if approved and isinstance(payload, dict) and str(payload.get("mode", "")).strip().lower() == "enforce":
            approved_for_enforce.append(cid)

    # 1) GET before
    r0 = _graph("GET", headers, AUTHZ_URL, timeout_s=30)
    if r0.status_code >= 400:
        for cid in target_ids:
            ctx["results"][cid] = (
                "NOT_EVALUATED",
                "AUTHZPOLICY_READ_FAILED",
                f"GET authorizationPolicy failed ({r0.status_code})",
                {"httpStatus": r0.status_code, "body": (r0.text or "")[:2000]},
                r0.status_code,
            )
        return ctx

    before = r0.json() or {}

    # Prepare per-control base evidence (before + desired). No PATCH here.
    for cid in target_ids:
        path, desired = CONTROL_FIELD_MAP[cid]
        cur_before = _get_path(before, path)
        details = {
            "before": {cid: cur_before},
            "desired": {cid: desired},
            "approvedForEnforce": cid in approved_for_enforce,
        }

        ctx["results"][cid] = (
            "NOT_EVALUATED",
            "AUTHZPOLICY_BULK_READY",
            "AuthorizationPolicy base context prepared (GET-before cached).",
            details,
            200,
        )

    ctx["beforeRaw"] = before
    ctx["approvedForEnforce"] = approved_for_enforce
    return ctx



def _make_per_control_enforcer(control_id: str):
    def _enforcer(*, tenant: dict, tenant_name: str, control: dict, control_id: str, headers: dict, approval: dict | None, mode: str):
        ctx = _run_bulk_once(tenant, tenant_name, headers)
        base = (ctx.get("results") or {}).get(control_id)

        # If bulk didn’t prepare this control, return conservative NOT_EVALUATED
        if not base:
            return (
                "NOT_EVALUATED",
                "AUTHZPOLICY_NOT_IN_BULKSET",
                "Control not included in AuthorizationPolicy bulk set.",
                {},
                200,
            )

        _state0, _rc0, _rd0, details, status = base

        # Determine compliance from before/after vs desired
        before_val = (details.get("before") or {}).get(control_id)
        desired_val = (details.get("desired") or {}).get(control_id)
        after_val = (details.get("after") or {}).get(control_id)

        compliant_before = (before_val == desired_val)
        compliant_after = (after_val == desired_val)

        mode_eff = (mode or "").strip().lower()

        if mode_eff == "report-only":
            if compliant_before:
                return ("COMPLIANT", "REPORT_ONLY_EVALUATED", "Report-only: already compliant (no changes applied).", details, int(status))
            return ("DRIFTED", "REPORT_ONLY_EVALUATED", "Report-only: drift detected (no changes applied).", details, int(status))

        if mode_eff == "enforce":
            # approval gating is enforced by main.py before calling registry enforcers

            if compliant_before:
                return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforce: already compliant (no change needed).", details, int(status))

            # PATCH ONLY THIS CONTROL'S FIELD
            path, desired = CONTROL_FIELD_MAP[control_id]
            patch_body = {}
            _set_dot_path(patch_body, path, desired)


            r1 = _graph("PATCH", headers, AUTHZ_URL, json_body=patch_body, timeout_s=30)
            details["applyStatus"] = int(r1.status_code)
            details["applyResponseText"] = (r1.text or "")[:2000]
            details["appliedPatchBody"] = patch_body

            if r1.status_code == 403:
                return ("NOT_EVALUATED", "AUTH_FORBIDDEN", "Enforce blocked: Graph returned 403 (insufficient privileges).", details, 403)

            if r1.status_code >= 400:
                details["applyError"] = {"httpStatus": r1.status_code, "body": (r1.text or "")[:2000]}
                return ("NOT_EVALUATED", "UNSUPPORTED_MODE", f"Enforce blocked: Graph PATCH failed (HTTP {r1.status_code}).", details, int(r1.status_code))

            # GET after (verify)
            r2 = _graph("GET", headers, AUTHZ_URL, timeout_s=30)
            details["afterReadStatus"] = int(r2.status_code)

            after = r2.json() if r2.status_code < 400 else None
            if isinstance(after, dict):
                after_val = _get_path(after, path)
                details["after"] = {control_id: after_val}
            else:
                details["after"] = {control_id: None}
                details["afterReadError"] = {"httpStatus": r2.status_code, "body": (r2.text or "")[:2000]}

            compliant_after = (details.get("after") or {}).get(control_id) == desired

            if compliant_after:
                return ("UPDATED", "ENFORCER_EXECUTED", "Enforce: applied AuthorizationPolicy change and verified.", details, int(r2.status_code) if r2.status_code else int(status))

            # PATCH succeeded but after-state didn't match -> tenant constraint / not persisted
            return ("NOT_EVALUATED", "UNSUPPORTED_MODE", "Enforce attempted but setting did not persist (tenant constraint or policy restriction).", details, int(r2.status_code) if r2.status_code else int(status))

    return _enforcer


# Register per-control enforcers (so main.py registry dispatch finds them) :contentReference[oaicite:4]{index=4}
for _cid in CONTROL_FIELD_MAP.keys():
    register(_cid, _make_per_control_enforcer(_cid))
