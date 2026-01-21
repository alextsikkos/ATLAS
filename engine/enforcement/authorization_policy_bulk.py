from __future__ import annotations

import time
import requests
from typing import Any, Dict, Tuple

from engine.enforcement.registry import register
from engine.approvals.reader import is_control_approved


AUTHZ_URL = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"

# controlId -> (json_path, desired_value)
CONTROL_FIELD_MAP = {
    # authorizationPolicy root fields
    "GuestInvitesRestrictedToAdminsAndGuestInviters": ("allowInvitesFrom", "adminsAndGuestInviters"),
    "EmailVerifiedUsersCannotJoinOrganization": ("allowEmailVerifiedUsersToJoinOrganization", False),
    "EmailBasedSubscriptionsDisabled": ("allowedToSignUpEmailBasedSubscriptions", False),
    "BlockMsolPowerShellEnabled": ("blockMsolPowerShell", True),

    # defaultUserRolePermissions fields
    "DefaultUserRoleAppsCreationDisabled": ("defaultUserRolePermissions.allowedToCreateApps", False),
    "DefaultUserRoleSecurityGroupsCreationDisabled": ("defaultUserRolePermissions.allowedToCreateSecurityGroups", False),
    "DefaultUserRoleTenantCreationDisabled": ("defaultUserRolePermissions.allowedToCreateTenants", False),
}



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
    Stores per-control outcomes in tenant["_authz_bulk"].
    """
    ctx = tenant.setdefault("_authz_bulk", {})
    if ctx.get("ran"):
        return ctx

    ctx["ran"] = True
    ctx["results"] = {}  # controlId -> tuple(state, reasonCode, reasonDetail, details, status)

    matched = tenant.get("_atlas_matched_controls") or []
    present_ids = {((c.get("atlasControlId") or c.get("controlId") or "")).strip() for c in matched if isinstance(c, dict)}

    target_ids = list(CONTROL_FIELD_MAP.keys())

    # Nothing to do
    if not target_ids:
        return ctx

    # Resolve which controls are approved for enforce (file-based approvals)
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

    # Build PATCH payload ONLY for approved enforce controls
    patch_body: dict[str, Any] = {}
    desired_by_cid: dict[str, Any] = {}

    for cid in approved_for_enforce:
        path, desired = CONTROL_FIELD_MAP[cid]
        _set_path(patch_body, path, desired)
        desired_by_cid[cid] = desired

    # 2) PATCH (only if we have at least one enforce control)
    patch_status = 200
    patch_error = None
    if patch_body:
        r1 = _graph("PATCH", headers, AUTHZ_URL, json_body=patch_body, timeout_s=30)
        patch_status = r1.status_code
        if r1.status_code >= 400:
            patch_error = {"httpStatus": r1.status_code, "body": (r1.text or "")[:2000]}

    # 3) GET after (even if PATCH failed; we want evidence)
    r2 = _graph("GET", headers, AUTHZ_URL, timeout_s=30)
    after = r2.json() if r2.status_code < 400 else None

    # Populate per-control results (report-only or enforce outcomes are decided per-control at call time)
    for cid in target_ids:
        path, desired = CONTROL_FIELD_MAP[cid]
        cur_before = _get_path(before, path)

        details = {
            "before": {cid: cur_before},
            "desired": {cid: desired},
        }

        if isinstance(after, dict):
            details["after"] = {cid: _get_path(after, path)}
        else:
            details["after"] = {cid: None}
            details["afterReadError"] = {"httpStatus": r2.status_code, "body": (r2.text or "")[:2000]}

        if patch_error is not None:
            details["applyError"] = patch_error
            details["appliedPatchBody"] = patch_body

        # Default to report-only style evaluation; the per-control enforcer will map to mode passed in
        ctx["results"][cid] = (
            "NOT_EVALUATED",
            "AUTHZPOLICY_BULK_READY",
            "AuthorizationPolicy bulk context prepared.",
            details,
            200 if r2.status_code < 400 else int(r2.status_code),
        )

    ctx["beforeRaw"] = before
    ctx["afterRaw"] = after
    ctx["approvedForEnforce"] = approved_for_enforce
    ctx["patchAttempted"] = bool(patch_body)
    ctx["patchStatus"] = patch_status
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
            # approval gating is already enforced by main.py before calling registry enforcers :contentReference[oaicite:3]{index=3}
            if compliant_before and compliant_after:
                return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforce: already compliant (no change needed).", details, int(status))
            if (not compliant_before) and compliant_after:
                return ("UPDATED", "ENFORCER_EXECUTED", "Enforce: applied AuthorizationPolicy change and verified.", details, int(status))
            return ("ERROR", "ENFORCER_ERROR", "Enforce: attempted but could not verify desired state.", details, int(status))

        return ("NOT_EVALUATED", "UNSUPPORTED_MODE", f"Unsupported mode for enforcer: {mode}", details, int(status))

    return _enforcer


# Register per-control enforcers (so main.py registry dispatch finds them) :contentReference[oaicite:4]{index=4}
for _cid in CONTROL_FIELD_MAP.keys():
    register(_cid, _make_per_control_enforcer(_cid))
