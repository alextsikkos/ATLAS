import requests

from engine.auth.token import graph_headers


def detect_disable_user_consent_to_apps_status(tenant: dict):
    """
    Detect whether user consent to apps is restricted/disabled.

    Uses: GET https://graph.microsoft.com/v1.0/policies/authorizationPolicy

    COMPLIANT: permissionGrantPoliciesAssigned is non-empty (consent restricted via policies)
    DRIFTED: permissionGrantPoliciesAssigned missing/empty (broad user consent likely enabled)
    ERROR: Graph call fails
    """
    headers = graph_headers(tenant)
    url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"

    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code >= 300:
        return "ERROR", {
            "reason": "Graph request failed",
            "status": r.status_code,
            "body": r.text[:2000],
        }

    ap = r.json()

    perms = (
        ap.get("defaultUserRolePermissions", {})
          .get("permissionGrantPoliciesAssigned", None)
    )

    if not perms:
        return "DRIFTED", {
            "reason": "Default user role has no permission grant policies assigned (broad user consent likely enabled)",
            "permissionGrantPoliciesAssigned": perms,
        }

    return "COMPLIANT", {
        "permissionGrantPoliciesAssigned": perms,
        "note": "Permission grant policies are assigned to the default user role (user consent is restricted).",
    }
def detect_self_service_password_reset_status(tenant: dict):
    """
    Detect whether Self Service Password Reset (SSPR) is enabled tenant-wide.

    Uses: GET https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy

    COMPLIANT: isSelfServicePasswordResetEnabled == True
    DRIFTED: False or missing
    ERROR: Graph call fails
    """
    headers = graph_headers(tenant)
    url = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"

    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code >= 300:
        return "ERROR", {
            "reason": "Graph request failed",
            "status": r.status_code,
            "body": r.text[:2000],
        }

    policy = r.json()
    enabled = policy.get("isSelfServicePasswordResetEnabled", None)

    if enabled is True:
        return "COMPLIANT", {
            "isSelfServicePasswordResetEnabled": True
        }

    return "DRIFTED", {
        "reason": "SSPR is not enabled (tenant-level flag false or missing)",
        "isSelfServicePasswordResetEnabled": enabled
    }
def detect_tier3_auth_methods_readiness(tenant: dict):
    """
    Tier 3 readiness check for phishing-resistant MFA availability.

    We look at Authentication Methods Policy configurations and report whether:
      - FIDO2 is enabled
      - Windows Hello for Business (WHfB) is enabled
      - Temporary Access Pass (TAP) is enabled (recommended bootstrap)

    COMPLIANT: At least one phishing-resistant method (FIDO2 or WHfB) is enabled
    DRIFTED: Both FIDO2 and WHfB are disabled/not enabled
    ERROR: Graph call fails
    """
    headers = graph_headers(tenant)
    url = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"


    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code >= 300:
        return "ERROR", {
            "reason": "Graph request failed",
            "status": r.status_code,
            "body": r.text[:2000],
        }

    data = r.json() or {}
    configs = data.get("authenticationMethodConfigurations", []) or []


    # Pull out the method states we care about.
    # Graph returns an array of method configurations with @odata.type.
    states = {
        "fido2": "unknown",
        "windowsHelloForBusiness": "unknown",
        "temporaryAccessPass": "unknown",
    }

    raw = {}
    for c in configs:
        otype = (c.get("@odata.type") or "").lower()

        if "fido2" in otype:
            states["fido2"] = c.get("state")
            raw["fido2"] = c
        elif "windowshelloforbusiness" in otype:
            states["windowsHelloForBusiness"] = c.get("state")
            raw["windowsHelloForBusiness"] = c
        elif "temporaryaccesspass" in otype:
            states["temporaryAccessPass"] = c.get("state")
            raw["temporaryAccessPass"] = c

    # Normalise state checks (Graph uses "enabled"/"disabled" typically)
    fido_on = (states["fido2"] or "").lower() == "enabled"
    whfb_on = (states["windowsHelloForBusiness"] or "").lower() == "enabled"
    tap_on = (states["temporaryAccessPass"] or "").lower() == "enabled"

    phishing_resistant_ready = fido_on or whfb_on

    details = {
        "methodStates": states,
        "phishingResistantReady": phishing_resistant_ready,
        "tapEnabled": tap_on,
        "recommendations": [],
    }

    if not phishing_resistant_ready:
        details["recommendations"].append("Enable FIDO2 and/or Windows Hello for Business in Authentication Methods Policy before enforcing Tier 3 phishing-resistant MFA controls.")

    if not tap_on:
        details["recommendations"].append("Consider enabling Temporary Access Pass (TAP) for safe onboarding/bootstrap of phishing-resistant methods.")

    if phishing_resistant_ready:
        return "COMPLIANT", details

    return "DRIFTED", details
def detect_tier3_break_glass_readiness(tenant: dict):
    """
    Tier 3 readiness check for break-glass safety.

    Checks:
      - breakGlassGroupId exists in tenant config
      - group exists in Entra ID
      - group has >= 2 members
      - members are enabled users

    This is detect-only and never enforces.
    """
    group_id = tenant.get("breakGlassGroupId")
    if not group_id:
        return "DRIFTED", {
            "reason": "breakGlassGroupId not defined in tenant configuration",
            "members": [],
        }

    headers = graph_headers(tenant)

    # Get group
    group_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}"
    g = requests.get(group_url, headers=headers, timeout=30)
    if g.status_code >= 300:
        return "ERROR", {
            "reason": "Failed to retrieve break-glass group",
            "status": g.status_code,
            "body": g.text[:2000],
        }

    # Get group members
    members_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/microsoft.graph.user?$select=id,displayName,userPrincipalName,accountEnabled"
    m = requests.get(members_url, headers=headers, timeout=30)
    if m.status_code >= 300:
        return "ERROR", {
            "reason": "Failed to retrieve break-glass group members",
            "status": m.status_code,
            "body": m.text[:2000],
        }

    members = m.json().get("value", []) or []

    enabled_members = []
    for user in members:
        if user.get("@odata.type") == "#microsoft.graph.user":
            if user.get("accountEnabled") is True:
                enabled_members.append({
                    "id": user.get("id"),
                    "displayName": user.get("displayName"),
                    "userPrincipalName": user.get("userPrincipalName"),
                })

    details = {
        "groupId": group_id,
        "totalMembers": len(members),
        "enabledMembers": enabled_members,
    }

    if len(enabled_members) >= 2:
        return "COMPLIANT", details

    return "DRIFTED", {
        **details,
        "reason": "Break-glass group should contain at least two enabled user accounts",
    }
# =========================
# Entra ID batch detectors
# (append-only, conservative)
# =========================

def _graph_get_json(tenant: dict, url: str):
    """
    Small helper for entra.py detectors:
    Returns: (ok: bool, data_or_error: dict)
    """
    headers = graph_headers(tenant)
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code >= 300:
        return False, {
            "reason": "Graph request failed",
            "url": url,
            "status": r.status_code,
            "body": (r.text or "")[:2000],
        }
    return True, (r.json() or {})


def _get_global_admin_role_id(tenant: dict):
    """
    Returns: (ok: bool, role_id_or_error: str|dict)
    Uses roleTemplateId for Global Administrator.
    """
    # Global Administrator roleTemplateId
    ga_template_id = "62e90394-69f5-4237-9190-012177145e10"
    url = f"https://graph.microsoft.com/v1.0/directoryRoles?$filter=roleTemplateId eq '{ga_template_id}'"
    ok, data = _graph_get_json(tenant, url)
    if not ok:
        return False, data

    roles = data.get("value", []) or []
    if not roles:
        return True, None  # not activated / not visible => NOT_EVALUATED by caller

    return True, roles[0].get("id")


def _list_directory_role_members(tenant: dict, role_id: str):
    """
    Returns: (ok: bool, members_or_error: list|dict)
    """
    # We want a few user fields; Graph may omit some depending on permissions.
    url = f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members?$select=id,displayName,userPrincipalName,onPremisesSyncEnabled,accountEnabled"
    ok, data = _graph_get_json(tenant, url)
    if not ok:
        return False, data
    return True, (data.get("value", []) or [])


def detect_global_admin_count_optimised_status(tenant: dict):
    """
    Control: GlobalAdminCountOptimised
    Conservative logic:
      - Count enabled USER objects in Global Administrator role membership.
    COMPLIANT: count <= 5
    DRIFTED: count > 5
    NOT_EVALUATED: GA directoryRole not present (not activated) OR cannot enumerate
    ERROR: Graph failures
    """
    ok, role_id_or_err = _get_global_admin_role_id(tenant)
    if not ok:
        return "ERROR", role_id_or_err

    role_id = role_id_or_err
    if not role_id:
        return "NOT_EVALUATED", {
            "reason": "Global Administrator directoryRole not found (role may not be activated/visible via Graph)",
        }

    ok, members_or_err = _list_directory_role_members(tenant, role_id)
    if not ok:
        return "ERROR", members_or_err

    members = members_or_err

    enabled_users = []
    non_user_objects = 0
    unknown_enabled = 0

    for m in members:
        otype = (m.get("@odata.type") or "").lower()
        if "user" not in otype:
            non_user_objects += 1
            continue

        # accountEnabled may be missing depending on directory permissions
        ae = m.get("accountEnabled", None)
        if ae is True:
            enabled_users.append({
                "id": m.get("id"),
                "displayName": m.get("displayName"),
                "userPrincipalName": m.get("userPrincipalName"),
                "onPremisesSyncEnabled": m.get("onPremisesSyncEnabled", None),
            })
        elif ae is None:
            unknown_enabled += 1

    count_enabled = len(enabled_users)

    details = {
        "globalAdmin": {
            "enabledUserCount": count_enabled,
            "unknownAccountEnabledCount": unknown_enabled,
            "nonUserMemberObjectsSkipped": non_user_objects,
            "sampleEnabledUsers": enabled_users[:25],
            "threshold": 5,
        },
    }

    if count_enabled <= 5:
        return "COMPLIANT", details

    return "DRIFTED", details


def detect_admin_accounts_separate_cloud_only_status(tenant: dict):
    """
    Control: AdminAccountsSeparateCloudOnly
    Conservative check (cloud-only aspect only):
      - Enumerate Global Administrator enabled users
      - DRIFTED if any have onPremisesSyncEnabled == True
      - COMPLIANT if none are synced (all False/None)
      - NOT_EVALUATED if GA role not visible
    NOTE: This does NOT prove 'separate accounts' — only cloud-only admin accounts.
    """
    ok, role_id_or_err = _get_global_admin_role_id(tenant)
    if not ok:
        return "ERROR", role_id_or_err

    role_id = role_id_or_err
    if not role_id:
        return "NOT_EVALUATED", {
            "reason": "Global Administrator directoryRole not found (role may not be activated/visible via Graph)",
        }

    ok, members_or_err = _list_directory_role_members(tenant, role_id)
    if not ok:
        return "ERROR", members_or_err

    members = members_or_err

    synced = []
    checked = 0
    unknown_sync = 0

    for m in members:
        otype = (m.get("@odata.type") or "").lower()
        if "user" not in otype:
            continue

        checked += 1
        sync = m.get("onPremisesSyncEnabled", None)
        if sync is True:
            synced.append({
                "id": m.get("id"),
                "displayName": m.get("displayName"),
                "userPrincipalName": m.get("userPrincipalName"),
                "onPremisesSyncEnabled": True,
            })
        elif sync is None:
            unknown_sync += 1

    details = {
        "checkedGlobalAdminUsers": checked,
        "syncedGlobalAdminUsers": synced,
        "unknownOnPremSyncCount": unknown_sync,
        "note": "This detector validates 'cloud-only' admin accounts by checking onPremisesSyncEnabled for Global Administrator members.",
    }

    if synced:
        return "DRIFTED", details

    # Conservative: if we cannot prove cloud-only for all checked admins,
    # do not claim COMPLIANT.
    if unknown_sync > 0:
        return "NOT_EVALUATED", {
            **details,
            "reason": "onPremisesSyncEnabled was not returned for one or more Global Administrator users; cannot prove cloud-only admin accounts.",
        }

    return "COMPLIANT", details



def detect_admin_consent_workflow_enabled_status(tenant: dict):
    """
    Control: AdminConsentWorkflowEnabled
    Uses: GET /policies/adminConsentRequestPolicy
    COMPLIANT: isEnabled == True
    DRIFTED: isEnabled == False
    ERROR: Graph failures
    """
    url = "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"
    ok, data = _graph_get_json(tenant, url)
    if not ok:
        return "ERROR", data

    enabled = data.get("isEnabled", None)

    details = {
        "isEnabled": enabled,
        "raw": data,
    }

    if enabled is True:
        return "COMPLIANT", details

    if enabled is False:
        return "DRIFTED", details

    return "NOT_EVALUATED", {
        "reason": "Graph response did not include isEnabled (missing surface/permissions)",
        "rawKeys": sorted(list(data.keys())),
    }


def detect_limited_admin_roles_azure_management_status(tenant: dict):
    """
    Control: LimitedAdminRolesAzureManagement
    Conservative interpretation:
      - Find service principal for 'Microsoft Azure Management' (Azure portal)
      - Check appRoleAssignmentRequired
    COMPLIANT: appRoleAssignmentRequired == True
    DRIFTED: appRoleAssignmentRequired == False
    NOT_EVALUATED: SP not found
    ERROR: Graph failures
    """
    azure_mgmt_app_id = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{azure_mgmt_app_id}'&$select=id,displayName,appId,appRoleAssignmentRequired"
    ok, data = _graph_get_json(tenant, url)
    if not ok:
        return "ERROR", data

    sps = data.get("value", []) or []
    if not sps:
        return "NOT_EVALUATED", {
            "reason": "Microsoft Azure Management service principal not found via Graph",
            "appId": azure_mgmt_app_id,
        }

    sp = sps[0]
    aar = sp.get("appRoleAssignmentRequired", None)

    details = {
        "servicePrincipal": sp,
    }

    if aar is True:
        return "COMPLIANT", details

    if aar is False:
        return "DRIFTED", details

    return "NOT_EVALUATED", {
        "reason": "Graph response did not include appRoleAssignmentRequired (missing surface/permissions)",
        "servicePrincipalKeys": sorted(list(sp.keys())),
    }


def detect_role_overlap_status(tenant: dict):
    """
    Control: RoleOverlap
    Conservative check:
      - Enumerate selected privileged directoryRoles (by displayName match)
      - Find users present in >1 of these roles
    COMPLIANT: no overlaps
    DRIFTED: overlaps found
    NOT_EVALUATED: cannot enumerate directoryRoles/members
    """
    # Target a small, high-privilege set to avoid noisy false positives
    target_role_names = {
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "Conditional Access Administrator",
        "Authentication Policy Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Teams Administrator",
        "Cloud Application Administrator",
        "Application Administrator",
        "User Administrator",
    }

    # List directory roles (activated roles only)
    url = "https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName"
    ok, data = _graph_get_json(tenant, url)
    if not ok:
        return "ERROR", data

    roles = data.get("value", []) or []
    if not roles:
        return "NOT_EVALUATED", {
            "reason": "No directoryRoles returned (missing surface/permissions or no activated roles)",
        }

    selected = [r for r in roles if (r.get("displayName") in target_role_names)]
    if not selected:
        return "NOT_EVALUATED", {
            "reason": "No target privileged roles found among activated directoryRoles",
            "activatedRoleCount": len(roles),
        }

    user_roles = {}  # userId -> {upn, displayName, roles: []}

    for r in selected:
        rid = r.get("id")
        rname = r.get("displayName")
        if not rid:
            continue

        ok, members_or_err = _list_directory_role_members(tenant, rid)
        if not ok:
            # do not guess; prove missing data
            return "NOT_EVALUATED", {
                "reason": "Failed to enumerate directoryRole members for overlap check",
                "role": r,
                "error": members_or_err,
            }

        for m in members_or_err:
            otype = (m.get("@odata.type") or "").lower()
            if "user" not in otype:
                continue

            uid = m.get("id")
            if not uid:
                continue

            entry = user_roles.get(uid) or {
                "id": uid,
                "displayName": m.get("displayName"),
                "userPrincipalName": m.get("userPrincipalName"),
                "roles": [],
            }
            if rname not in entry["roles"]:
                entry["roles"].append(rname)
            user_roles[uid] = entry

    overlaps = [u for u in user_roles.values() if len(u.get("roles", [])) > 1]

    details = {
        "targetRoleNames": sorted(list(target_role_names)),
        "selectedRoleCount": len(selected),
        "userCountSeenInTargetRoles": len(user_roles),
        "overlapUsers": overlaps[:50],
        "overlapCount": len(overlaps),
    }

    if overlaps:
        return "DRIFTED", details

    return "COMPLIANT", details
