# engine/main.py
import argparse, json, os, time
import sys
from .auth.token import graph_headers
from .audit.logger import write_json, utc_stamp
from .detection.secure_score import fetch_secure_score, fetch_control_profiles, build_findings
from engine.audit.events import write_audit_event
import engine.enforcement  # ensures enforcer registry modules are loaded
_CURRENT_CONTROL_STARTED_AT: float | None = None  # set per-control for durationSeconds in audit events
from engine.audit.hardening import harden_audit_event_inplace
from engine.enforcement.ensure import ensure_policy
from engine.enforcement.policies.risky_signin_mfa import DISPLAY_NAME as RS_DISPLAY_NAME, build_payload as build_rs_payload
from engine.enforcement.policies.risky_user_password import DISPLAY_NAME as RUP_DISPLAY_NAME, build_payload as build_rup_payload
from engine.enforcement.policies.admin_mfa import build_payload as build_am_payload
from engine.registry.loader import load_controls
from engine.approvals.reader import is_control_approved
from engine.enforcement.policies.block_legacy_auth import DISPLAY_NAME as BLA_DISPLAY_NAME, build_payload as build_bla_payload
from engine.graph.client import GraphClient
from engine.detectors.spo import run_spo_tenant_settings
from engine.detectors.spo_batch_a import (
    detect_onedrive_block_sync_unmanaged_devices,
    detect_sharepoint_guest_users_cannot_reshare,
    detect_sway_block_external_sharing,
)
from engine.detectors.teams import run_teams_tenant_settings
from engine.detectors.teams_meeting import (
    run_teams_meeting_policies,
    detect_teams_auto_admit_invited_only_status,
    detect_teams_designated_presenter_configured_status,
    detect_teams_limit_external_control_status,
    detect_teams_restrict_anonymous_join_status,
    detect_teams_restrict_anonymous_start_meeting_status,
    detect_teams_restrict_dialin_bypass_lobby_status,
)
from engine.tier3.gates import (
    attach_reason,
    return_not_evaluated,
    safety_block_if_no_break_glass,
    tier3_requires_acknowledgements,
    missing_tier3_ack_fields,
)

def _write_audit_event_timed(tenant_name, audit: dict, started_at: float | None = None):
    # Fall back to current control start time if caller didn't pass started_at
    global _CURRENT_CONTROL_STARTED_AT
    # Ensure tenant always present in audit payloads (even when started_at is provided)
    audit.setdefault("tenant", tenant_name)

    if started_at is None:
        started_at = _CURRENT_CONTROL_STARTED_AT
        # --- Hardening: ensure every audit has state + reason fields (never blank) ---
        try:
            harden_audit_event_inplace(audit)
        except Exception:
            # Best-effort only; auditing must never break
            pass
        # --- end hardening ---



    if started_at is not None:
        try:
            audit["durationSeconds"] = round(time.perf_counter() - started_at, 3)
        except Exception:
            audit["durationSeconds"] = None
            audit["durationMissing"] = True
    else:
        audit["durationSeconds"] = None
        audit["durationMissing"] = True
    # Record timing for end-of-run summary (best-effort; never break auditing)
    global _CONTROL_TIMINGS
    try:
        _CONTROL_TIMINGS.append({
            "controlId": audit.get("controlId"),
            "controlName": audit.get("controlName") or audit.get("name"),
            "category": audit.get("category"),
            "tier": audit.get("tier"),
            "mode": audit.get("mode"),
            "state": audit.get("state"),
            "reasonCode": audit.get("reasonCode"),
            "durationSeconds": audit.get("durationSeconds"),
        })
    except Exception:
        pass

    # IMPORTANT: write the audit event (do NOT call this function again)
    return write_audit_event(tenant_name, audit)


def load_tenant(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
def normalize_detector_result(result):
    """
    Allows detectors to return either:
      - (state, details)
      - {"state": "...", "details": {...}, "reasonCode": "...", "reasonDetail": "..."}
    Always returns: (state, details)

    Additive hardening:
      - Ensures details is a dict
      - Ensures details always has reasonCode + reasonDetail
      - Preserves reasonCode/reasonDetail if detector provided them
    """

    def _ensure_dict(d):
        if d is None:
            return {}
        if isinstance(d, dict):
            return d
        return {"value": d}

    def _defaults_for(state: str):
        s = (state or "").upper()
        if s == "COMPLIANT":
            return ("COMPLIANT", "Detector evaluated the control as compliant.")
        if s == "DRIFTED":
            return ("DRIFTED", "Detector evaluated the control as non-compliant (drift detected).")
        if s == "NOT_EVALUATED":
            return ("NOT_EVALUATED", "Detector did not evaluate this control (blocked, missing data, not applicable, or error).")
        if s:
            return (s, f"Detector returned state={s}.")
        return ("NOT_EVALUATED", "Detector returned no state.")

    # Format: (state, details)
    if isinstance(result, tuple) and len(result) == 2:
        state = result[0]
        details = _ensure_dict(result[1])

        # If detector already embedded reason fields in details, keep them.
        if "reasonCode" not in details or "reasonDetail" not in details:
            rc, rd = _defaults_for(str(state) if state is not None else "")
            details.setdefault("reasonCode", rc)
            details.setdefault("reasonDetail", rd)

        return state, details

    # Format: dict with state/details (+ optional reason fields)
    if isinstance(result, dict):
        state = result.get("state")
        details = _ensure_dict(result.get("details"))

        # Preserve detector-supplied reason fields (either top-level or inside details)
        top_rc = result.get("reasonCode")
        top_rd = result.get("reasonDetail")

        if top_rc is not None:
            details.setdefault("reasonCode", top_rc)
        if top_rd is not None:
            details.setdefault("reasonDetail", top_rd)

        # Backfill defaults if still missing
        if "reasonCode" not in details or "reasonDetail" not in details:
            rc, rd = _defaults_for(str(state) if state is not None else "")
            details.setdefault("reasonCode", rc)
            details.setdefault("reasonDetail", rd)

        # If it looks valid, return it
        if isinstance(state, str) and state.strip():
            return state, details

        # Dict but missing usable state
        rc, rd = _defaults_for("NOT_EVALUATED")
        details.setdefault("reasonCode", rc)
        details.setdefault("reasonDetail", "Detector returned dict without a valid 'state' field.")
        details.setdefault("raw", result)
        return "NOT_EVALUATED", details

    # Anything else
    details = {
        "error": "Detector returned unexpected type",
        "rawType": str(type(result)),
    }
    rc, rd = _defaults_for("NOT_EVALUATED")
    details.setdefault("reasonCode", rc)
    details.setdefault("reasonDetail", rd)
    return "NOT_EVALUATED", details


def get_ca_policy_by_display_name(headers: dict, display_name: str):
    """
    Returns: (policy_or_none, debug_dict)
    """
    import requests

    base = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    url = base

    target = display_name.strip().lower()
    seen_names = []
    seen_count = 0

    while url:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json() or {}

        vals = data.get("value", []) or []
        seen_count += len(vals)

        for p in vals:
            name = (p.get("displayName") or "").strip()
            if name and len(seen_names) < 25:
                seen_names.append(name)

            lname = name.lower()
            if lname == target or lname.startswith("atlas - block legacy"):
                return p, {
                    "seenCount": seen_count,
                    "sampleNames": seen_names,
                    "matchedBy": "exact" if lname == target else "prefix",
                }

        url = data.get("@odata.nextLink")

    return None, {
        "seenCount": seen_count,
        "sampleNames": seen_names,
        "matchedBy": None,
    }

def get_auth_strength_policy_id_by_name(headers: dict, display_name: str) -> str | None:
    import requests

    url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies"
    try:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        for p in (r.json() or {}).get("value", []) or []:
            if (p.get("displayName") or "").strip().lower() == display_name.strip().lower():
                return p.get("id")
    except Exception:
        return None
    return None
def get_security_defaults_status(headers: dict) -> bool | None:
    """
    Returns True if Security Defaults enabled, False if disabled, None if unreadable.
    """
    import requests
    url = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    try:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        body = r.json() or {}
        return bool(body.get("isEnabled"))
    except Exception:
        return None

def find_legacy_auth_blocking_policy(headers: dict) -> dict:
    """
    Conservative detector for a CA policy that blocks legacy auth.
    Looks for:
      - grantControls includes 'block'
      - conditions.clientAppTypes includes exchangeActiveSync and/or other
    Returns a dict:
      {found: bool, enabled: bool, policyId, displayName, ...} (when found)
    """
    import requests
    url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    items = (r.json() or {}).get("value", []) or []

    for p in items:
        conditions = p.get("conditions") or {}
        client_app_types = conditions.get("clientAppTypes") or []
        grant = p.get("grantControls") or {}
        built_in = grant.get("builtInControls") or []
        state = p.get("state")

        built_in_l = [(x or "").lower() for x in built_in if isinstance(x, str)]
        if "block" not in built_in_l:
            continue

        # Legacy auth in CA is typically represented as exchangeActiveSync/other in clientAppTypes
        if any(x in client_app_types for x in ["exchangeActiveSync", "other"]):
            return {
                "found": True,
                "enabled": (state == "enabled"),
                "policyId": p.get("id"),
                "displayName": p.get("displayName"),
                "state": state,
                "clientAppTypes": client_app_types,
                "builtInControls": built_in,
            }

    return {"found": False}

def get_break_glass_user_ids(tenant: dict) -> list[str]:
    ids = tenant.get("breakGlassUserIds") or []
    # Normalize: strip empties
    ids = [x.strip() for x in ids if isinstance(x, str) and x.strip()]
    return ids
def get_break_glass_group_id(tenant: dict) -> str | None:
    gid = tenant.get("breakGlassGroupId")
    if isinstance(gid, str):
        gid = gid.strip()
    return gid if gid else None

# --- Capability Matrix: controls with bespoke logic in main.py today ---
# Keep this list small and explicit; update when you add new detectors/enforcers.
CAPABILITY_CUSTOM_DETECTORS = {
    
    "SharePointModernAuthRequired",# DNS detectors
    "EXODKIMEnabledAllDomains",
    "EXODMARCAllDomains",

    # Entra detectors
    "DisableUserConsentToApps",
    "Tier3AuthMethodsReadiness",
    "Tier3BreakGlassReadiness",
    "AdminConsentWorkflowEnabled",
    "MDOBlockAutoForwarding",
    "CustomBannedPasswords",
    "PasswordProtection",
    "Tier3AuthMethodsProbe",
    "Tier3AuthMethodsCatalog",
    "IntegratedAppsRestricted",
    "ThirdPartyAppsRestricted",
    "AuthMethodsSoftwareOathEnabled",
    "Tier3AuthorizationPolicyProbe",
    "AuthMethodsHardwareOathEnabled",
    "AuthMethodsX509CertificateDisabled",
    "AdminOwnedAppsRestricted",
    "GlobalAdminCountOptimised",
    "AdminAccountsSeparateCloudOnly",
    "LimitedAdminRolesAzureManagement",
    "RoleOverlap",
    "LinkedInConnectionsDisabled",



    # MDO detector (detect-only path exists)
    "MDOPresetSecurityPolicies",
    "EXOStorageProvidersRestricted",
    "MDOAntiMalware",
    "EXOMailTipsEnabled",
    "CustomerLockboxEnabled",
    "DefenderForIdentityDeployed",
    "MDOAntiSpam",
    "McasFirewallLogUpload",
    "AuditLogSearchEnabled",
    "MailboxAuditingEnabled",
    "SharePointDefaultLinkTypeRestricted",
    "SharePointDefaultSharingRestricted",
    "SharePointLinkExpirationConfigured",
    "SharePointExternalSharingManaged",
    "SharePointIdleSessionTimeout",
    "OneDriveExternalSharingRestricted",
    "OneDriveSyncRestricted",

    # Batch A: SPO/OneDrive/Sway (custom detect-only)
    "OneDriveBlockSyncUnmanagedDevices",
    "SharePointGuestUsersCannotReshare",
    "SwayBlockExternalSharing",
    # Batch B: Purview (custom detect-only)
    "PurviewAutoLabelingPolicies",
    "PurviewLabelConsentDataMap",
    "TeamsExternalAccessRestricted",
    "TeamsFederationRestricted",
    "TeamsFileSharingRestricted",
    "MDETamperProtectionStatus",
    "MDOAntiPhish",
    "MDOSafeAttachments",
    "MDOSafeLinks",
    "BlockLegacyAuthenticationStatus",
    "TeamsAutoAdmitInvitedOnly",
    "TeamsDesignatedPresenterConfigured",
    "TeamsLimitExternalControl",
    "TeamsRestrictAnonymousJoin",
    "TeamsRestrictAnonymousStartMeeting",
    "TeamsRestrictDialInBypassLobby",

    # --- EXO custom detectors ---
    "EXOCalendarExternalSharingDisabled",
    "EXOOutlookAddinsBlocked",
    "EXOSPFRecordsAllDomains",

    # --- MDO custom detectors ---
    "MDOAllowedSendersRestricted",
    "MDOBulkComplaintLevelThreshold",
    "MDOBulkSpamAction",
    "MDOHighConfidenceSpamAction",
    "MDOPhishingAction",
    "MDOThresholdReachedAction",
    "MDOQuarantineRetentionPeriod",
    "MDOSafeDocumentsEnabled",
    "MDOSafeLinksOfficeApps",
    "MDOSafetyTipsEnabled",
    "MDOSpamNotificationsAdminsOnly",
    "MDOAntiPhishingPoliciesTuned",
    "MDOMailboxIntelligenceActionsConfigured",
    "MDOMailboxIntelligenceProtection",
    "MDOPhishThresholdLevel",
    "MDOTargetedUsersProtection",
    "MDOTargetedDomainProtection",
    "MDOTargetedDomainProtectionAction",
    "MDOTargetedUserProtectionAction",
    "MDOTurnOnMDOForSPOODTeams",

}

CAPABILITY_ENFORCERS = {
    # Conditional Access / Graph enforcement paths in main.py
    "SigninRiskPolicy",
    "UserRiskPolicy",
    "AdminMFAV2",
    "DisableUserConsentToApps",
    "BlockLegacyAuthenticationPolicy",
    "SharePointPreventExternalUsersFromResharingEnabled",
    "SharePointDomainRestrictionConfigured",
    "CAAdminPhishingResistantMFA",
    "CAAdminSignInFrequencySessionTimeout",
    "SharePointDefaultLinkTypeRestricted",
    "GuestInvitesRestrictedToAdminsAndGuestInviters",
    "EmailVerifiedUsersCannotJoinOrganization",
    "EmailBasedSubscriptionsDisabled",
    "BlockMsolPowerShellEnabled",
    "DefaultUserRoleAppsCreationDisabled",
    "DefaultUserRoleSecurityGroupsCreationDisabled",
    "DefaultUserRoleTenantCreationDisabled",
    "ThirdPartyAppsRestricted",
    "AuthMethodsSmsDisabled",
    "AuthMethodsVoiceDisabled",
    "AuthMethodsTemporaryAccessPassHardened",
    "Tier3PerUserMfaReadiness",
    "AuthMethodsTemporaryAccessPassUsableOnce",
    "IntegratedAppsRestricted",
    "AdminOwnedAppsRestricted",
    "AuthMethodsMicrosoftAuthenticatorEnabled",
    "AuthMethodsFido2Enabled",
    "SharePointDefaultSharingRestricted",
    "SharePointLinkExpirationConfigured",

    # ATLAS-owned CA enforcers (with safety blocks)
    "CAAdminBlockLegacyAuth",
    "CAAllUsersBlockLegacyAuth",
    "CAAdminMFAAllApps",

    # Graph enforcement
    "SelfServicePasswordReset",

    # EXO / MDO enforcement
    "MDOPresetSecurityPolicies",    "SharePointSharingAllowedDomainListConfigured",
    "SharePointSharingBlockedDomainListConfigured",

}

# Controls we intend to implement fallback detectors for when Secure Score is missing/not exposed
FALLBACK_DETECTORS_PLANNED = {
    "TeamsExternalAccessRestricted",
    "TeamsFederationRestricted",
    "TeamsFileSharingRestricted",
    "SharePointDefaultSharingRestricted",
    "SharePointLinkExpirationConfigured",
    "SharePointDefaultLinkTypeRestricted",
    "SharePointDomainRestrictionConfigured",
    "SharePointSharingAllowedDomainListConfigured",
    "SharePointSharingBlockedDomainListConfigured",
    "SharePointPreventExternalUsersFromResharingEnabled",
    "SharePointGuestUsersCannotReshare",
    "OneDriveExternalSharingRestricted",
    "OneDriveSyncRestricted",
    "OneDriveBlockSyncUnmanagedDevices",
    "SwayBlockExternalSharing",
    "MDOBulkComplaintLevelThreshold",
}

def main():
    global _CURRENT_CONTROL_STARTED_AT
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", required=True, help="Path to tenant config JSON")
    args = ap.parse_args()
    tenant = load_tenant(args.tenant)
    global _CONTROL_TIMINGS
    _CONTROL_TIMINGS = []

    # Per-run EXO/IPP PowerShell cache (in-memory only)
    tenant["_exo_ps_cache"] = {}
    # --- Prewarm EXO snapshot once per run (keeps per-control timings meaningful) ---
    try:
        from engine.detectors import mdo as mdo_det
        # This will trigger exo_snapshot.ps1 on first EXO call and populate tenant["_exo_ps_cache"].
        # We intentionally do this BEFORE control timing starts, so the EXO connect cost isn't blamed on a random control.
        mdo_det._run_exo_ps("exo_mailtips_enabled.ps1", tenant, timeout_s=600)
    except Exception:
        # Never let prewarm break the run; detectors will surface any issues during evaluation.
        pass
    # --- end EXO prewarm ---
    # --- SPO app-only auth env (required to prevent interactive auth popups) ---
    try:
        spo_auth = (tenant or {}).get("spoAppAuth") or {}

        def _set_env(k: str, v):
            if v is None:
                os.environ.pop(k, None)
            else:
                s = str(v).strip()
                if s:
                    os.environ[k] = s
                else:
                    os.environ.pop(k, None)

        _set_env("ATLAS_SPO_CLIENT_ID", spo_auth.get("clientId"))
        _set_env("ATLAS_SPO_TENANT_ID", spo_auth.get("tenantId"))
        _set_env("ATLAS_SPO_CERT_THUMBPRINT", spo_auth.get("certificateThumbprint"))

        # Optional (only if you later support PFX-path auth)
        _set_env("ATLAS_SPO_CERT_PATH", spo_auth.get("certificatePath"))
        _set_env("ATLAS_SPO_CERT_PASSWORD", spo_auth.get("certificatePassword"))
    except Exception:
        # Never crash the run for env wiring; detectors will surface missingKeys if misconfigured.
        pass
    # --- end SPO env ---

    graph = GraphClient(tenant)
    headers = graph.headers
    tenant["graphHeaders"] = headers
    score = fetch_secure_score(headers)
    profiles = fetch_control_profiles(headers)
    findings = build_findings(score, profiles)
    tenant_name = tenant["tenant_name"]
    # --- Teams PowerShell auth (used by Teams custom detectors) ---
    ps_cfg = (tenant or {}).get("teamsPowershell") or (tenant or {}).get("exoPowershell") or {}

    tenant_id = (
        ((ps_cfg.get("auth") or {"tenantId": ps_cfg.get("tenantId")})).get("tenantId")
        or (((tenant or {}).get("auth") or {}).get("tenant_id"))
    )
    app_id = ps_cfg.get("appId")
    thumb = ps_cfg.get("certificateThumbprint")

    # Build a set of Secure Score control IDs that actually exist in this tenant's profiles.
    # If an ID isn't here, it usually means: not applicable to the tenant, not licensed, or not exposed.
    known_secure_score_ids = {p.get("id") for p in (profiles or []) if p.get("id")}

    # Load registry controls (controls.json)
    registry_controls = load_controls()
    registry_by_id = {c["id"]: c for c in registry_controls}

    # --- ATLAS visibility warning: Secure Score IDs referenced by controls.json but missing from tenant snapshot ---
    try:
        # Normalize everything so comparisons are reliable
        known_secure_score_ids = {
            (p.get("id") or "").strip().lower()
            for p in (profiles or [])
            if (p.get("id") or "").strip()
        }

        referenced_ids = set()
        for c in registry_controls:
            for ssid in (c.get("secureScoreControlIds") or []):
                key = (ssid or "").strip().lower()
                if key:
                    referenced_ids.add(key)

        missing_ss_ids = sorted(referenced_ids - known_secure_score_ids)

        if missing_ss_ids:
            print(
                f"\n[WARN] {len(missing_ss_ids)} Secure Score control IDs are referenced by ATLAS controls.json "
                f"but missing from this tenant's Secure Score controlProfiles:"
            )
            for mid in missing_ss_ids:
                print(f"  - {mid}")
            print("       These controls may show as NOT_EVALUATED in this tenant (not applicable / licensing / not exposed).\n")

    except Exception as e:
        print(f"\n[WARN] Failed to compute missing Secure Score IDs warning: {e}\n")
    # --- end warning block ---



    reg_by_id = {c["id"]: c for c in registry_controls if c.get("id")}
    ss_to_registry = {}
    for c in registry_controls:
        rid = c.get("id")
        for ssid in (c.get("secureScoreControlIds") or []):
            key = (ssid or "").strip().lower()
            if key:
                ss_to_registry.setdefault(key, []).append(rid)




    # Only run controls that exist in registry and are present in findings
    matched = []
    # Lookup findings by Secure Score controlId for quick access later
    findings_by_ssid = { (x.get("controlId") or "").strip().lower(): x for x in findings if x.get("controlId") }

    # Add each registry control ONCE as the base row
    matched = []
    for c in registry_controls:
        matched.append({
            "atlasControlId": c["id"],
            "controlId": c["id"],
            "scorePct": None,
            "title": c.get("name"),
            "implementationStatus": "",
            "actionUrl": "",
            # carry registry metadata forward so reporting can reason about mappings
            "secureScoreControlIds": (c.get("secureScoreControlIds") or []),
            "gapOnly": bool(c.get("gapOnly", False)),
            "tier": c.get("tier"),
            "category": c.get("category"),
        })





    # Build an index once so we don't do nested loops (scales better as controls grow)
    matched_by_id = {m.get("atlasControlId"): m for m in matched if m.get("atlasControlId")}

    for f in findings:
        ssid = f.get("controlId")
        key = (ssid or "").strip().lower()
        rid_list = ss_to_registry.get(key) or []


        if not rid_list:
            continue

        for rid in rid_list:
            m = matched_by_id.get(rid)
            if not m:
                continue
            m.update(f)
            m["atlasControlId"] = rid



    # Deduplicate by atlasControlId (prevents accidental double-appends)
    dedup = {}
    for m in matched:
        dedup[m["atlasControlId"]] = m
    matched = list(dedup.values())

    print(f"\nMatched {len(matched)} Atlas controls:")
    # --- Auth Preflight Summary (additive, Windows-safe) ---
    def _auth_preflight_summary(tenant: dict, matched_controls: list[dict]) -> None:
        tenant_name = (tenant or {}).get("tenant_name") or (tenant or {}).get("tenantName") or "(unknown)"
        tenant_domain = (tenant or {}).get("tenant_domain") or (tenant or {}).get("tenantDomain")
        # Persist preflight for evidence pack (non-fatal, additive)
        preflight_stamp = utc_stamp()
        preflight_out_dir = os.path.join("output", "preflight", str(tenant_name), preflight_stamp)
        preflight_path = os.path.join(preflight_out_dir, "auth_preflight.json")


        """
        Before running controls, print which auth paths are configured/available and
        which matched controls will be blocked due to missing auth configuration.

        This is intentionally conservative: it does NOT assume tenant state or licensing.
        It only reports what Atlas can/can't attempt based on provided config.
        """

        def _norm(s):
            return s.strip() if isinstance(s, str) else s

        tenant_name = (tenant or {}).get("tenant_name") or (tenant or {}).get("tenantName") or "(unknown)"
        tenant_domain = (tenant or {}).get("tenant_domain") or (tenant or {}).get("tenantDomain")

        # --- Graph (already used earlier in the run) ---
        auth = (tenant or {}).get("auth") or {}
        graph_tenant_id = _norm(auth.get("tenant_id") or auth.get("tenantId"))
        graph_client_id = _norm(auth.get("client_id") or auth.get("clientId"))
        graph_client_secret = _norm(auth.get("client_secret") or auth.get("clientSecret"))

        graph_missing = []
        if not graph_tenant_id:
            graph_missing.append("tenant.auth.tenant_id")
        if not graph_client_id:
            graph_missing.append("tenant.auth.client_id")
        if not graph_client_secret:
            graph_missing.append("tenant.auth.client_secret")

        graph_status = "READY" if not graph_missing else "NOT_CONFIGURED"
        graph_detail = "App-only Graph auth present" if not graph_missing else f"Missing: {', '.join(graph_missing)}"

        # --- EXO / IPPS (Purview) PowerShell ---
        exo_ps = (tenant or {}).get("exoPowershell") or {}
        exo_app = _norm(exo_ps.get("appId"))
        exo_thumb = _norm(exo_ps.get("certificateThumbprint"))
        exo_org = _norm(exo_ps.get("organization")) or _norm(tenant_domain)

        exo_missing = []
        if not exo_app:
            exo_missing.append("tenant.exoPowershell.appId")
        if not exo_thumb:
            exo_missing.append("tenant.exoPowershell.certificateThumbprint")
        if not exo_org:
            exo_missing.append("tenant.exoPowershell.organization (or tenant.tenant_domain)")

        exo_status = "CONFIGURED" if not exo_missing else "NOT_CONFIGURED"
        exo_detail = "App-only EXO/IPPSSession auth configured" if not exo_missing else f"Missing: {', '.join(exo_missing)}"

        # --- Teams PowerShell ---
        ps_cfg = (tenant or {}).get("teamsPowershell") or (tenant or {}).get("exoPowershell") or {}
        teams_tenant_id = _norm(((ps_cfg.get("auth") or {}).get("tenant_id")) or ((tenant or {}).get("auth") or {}).get("tenant_id"))
        teams_app_id = _norm(ps_cfg.get("appId"))
        teams_thumb = _norm(ps_cfg.get("certificateThumbprint"))

        teams_missing = []
        if not teams_tenant_id:
            teams_missing.append("tenant.teamsPowershell.auth.tenant_id (or tenant.auth.tenant_id)")
        if not teams_app_id:
            teams_missing.append("tenant.teamsPowershell.appId")
        if not teams_thumb:
            teams_missing.append("tenant.teamsPowershell.certificateThumbprint")

        teams_status = "CONFIGURED" if not teams_missing else "NOT_CONFIGURED"
        teams_detail = "App-only Teams PowerShell auth configured" if not teams_missing else f"Missing: {', '.join(teams_missing)}"

        # --- SharePoint Online PowerShell (SPO) ---
        admin_url = _norm((tenant or {}).get("spoAdminUrl"))
        spo_auth = (tenant or {}).get("spoAppAuth") or {}
        spo_client_id = _norm(spo_auth.get("clientId"))
        spo_tenant_id = _norm(spo_auth.get("tenantId"))
        spo_cert_tp = _norm(spo_auth.get("certificateThumbprint"))
        spo_cert_path = _norm(spo_auth.get("certificatePath"))

        spo_missing = []
        if not admin_url:
            spo_missing.append("tenant.spoAdminUrl")
        if not spo_client_id:
            spo_missing.append("tenant.spoAppAuth.clientId")
        if not spo_tenant_id:
            spo_missing.append("tenant.spoAppAuth.tenantId")
        if not (spo_cert_tp or spo_cert_path):
            spo_missing.append("tenant.spoAppAuth.certificateThumbprint (or certificatePath)")

        spo_status = "CONFIGURED" if not spo_missing else "NOT_CONFIGURED"
        spo_detail = "App-only SPO auth configured" if not spo_missing else f"Missing: {', '.join(spo_missing)}"

        # --- MCAS (Defender for Cloud Apps) ---
        mcas_cfg = (tenant or {}).get("mcas") or {}
        mcas_api = _norm(mcas_cfg.get("apiUrl") or mcas_cfg.get("api_url") or mcas_cfg.get("portalUrl") or mcas_cfg.get("portal_url"))

        mcas_missing = []
        if not mcas_api:
            mcas_missing.append("tenant.mcas.apiUrl")
        if graph_missing:
            mcas_missing.append("tenant.auth (tenant_id/client_id/client_secret)")

        mcas_status = "CONFIGURED" if not mcas_missing else "NOT_CONFIGURED"
        mcas_detail = "MCAS API configured" if not mcas_missing else f"Missing: {', '.join(mcas_missing)}"

        # Optional, best-effort: token acquisition test for MCAS (non-fatal).
        mcas_token_test = None
        if mcas_status == "CONFIGURED":
            try:
                from engine.detectors.mcas import _acquire_mcas_app_token

                tok, _tok_details = _acquire_mcas_app_token(str(graph_tenant_id), str(graph_client_id), str(graph_client_secret))
                mcas_token_test = "OK" if tok else "FAILED"
            except Exception:
                mcas_token_test = "SKIPPED"

        # Identify which matched controls will be blocked if a required auth path isn't configured.
        blocked: dict[str, list[str]] = {}

        def _add_blocked(reason: str, c: dict) -> None:
            blocked.setdefault(reason, []).append(f"{c.get('atlasControlId')} - {c.get('name','')}")

        for c in matched_controls or []:
            cid = c.get("atlasControlId")
            cat = c.get("category")

            if cid == "McasFirewallLogUpload":
                if mcas_status != "CONFIGURED":
                    _add_blocked("MCAS app-only auth missing", c)
                continue

            if cat in ("Identity", "Apps", "M365"):
                if graph_status != "READY":
                    _add_blocked("Graph app-only auth missing", c)
            elif cat in ("Email", "Data"):
                if exo_status != "CONFIGURED":
                    _add_blocked("EXO/IPPSSession app-only PowerShell auth missing", c)
            elif cat in ("SharePoint",):
                if spo_status != "CONFIGURED":
                    _add_blocked("SPO app-only PowerShell auth missing", c)
            elif cat in ("Collaboration",):
                if teams_status != "CONFIGURED":
                    _add_blocked("Teams app-only PowerShell auth missing", c)

        print("\n==== AUTH PREFLIGHT SUMMARY ====")
        print(f"Tenant: {tenant_name}")
        if tenant_domain:
            print(f"Tenant domain: {tenant_domain}")
        print("\nAuth paths:")
        print(f"  - Graph (App-only): {graph_status} | {graph_detail}")
        print(f"  - Exchange/IPPSSession (PowerShell): {exo_status} | {exo_detail}")
        print(f"  - Teams (PowerShell): {teams_status} | {teams_detail}")
        print(f"  - SharePoint Online (PowerShell): {spo_status} | {spo_detail}")
        if mcas_token_test:
            print(f"  - Defender for Cloud Apps (MCAS): {mcas_status} | {mcas_detail} | tokenTest={mcas_token_test}")
        else:
            print(f"  - Defender for Cloud Apps (MCAS): {mcas_status} | {mcas_detail}")

        if blocked:
            print("\nDetectors that will be BLOCKED (conservative, based on config):")
            for reason in sorted(blocked.keys()):
                items = blocked[reason]
                print(f"  - {reason}: {len(items)} control(s)")
                for it in items[:25]:
                    print(f"      * {it}")
                if len(items) > 25:
                    print(f"      * ... (+{len(items) - 25} more)")
        else:
            print("\nNo matched controls are blocked by missing auth configuration.")

        print("==== END AUTH PREFLIGHT ====")
        # Write preflight JSON (customer evidence pack)
        try:
            def _json_safe(obj):
                if obj is None:
                    return None
                if isinstance(obj, (str, int, float, bool)):
                    return obj
                if isinstance(obj, dict):
                    return {str(k): _json_safe(v) for k, v in obj.items()}
                if isinstance(obj, (list, tuple, set)):
                    return [_json_safe(v) for v in obj]
                return str(obj)

            preflight_payload = {
                "tenant": {
                    "name": tenant_name,
                    "domain": tenant_domain,
                },
                "generatedAt": preflight_stamp,
                "authPaths": {
                    "graph": {
                        "status": graph_status,
                        "detail": graph_detail,
                        "missing": graph_missing,
                    },
                    "exoIpps": {
                        "status": exo_status,
                        "detail": exo_detail,
                        "missing": exo_missing,
                    },
                    "teamsPs": {
                        "status": teams_status,
                        "detail": teams_detail,
                        "missing": teams_missing,
                    },
                    "spoPs": {
                        "status": spo_status,
                        "detail": spo_detail,
                        "missing": spo_missing,
                    },
                    "mcas": {
                        "status": mcas_status,
                        "detail": mcas_detail,
                        "missing": mcas_missing,
                        "tokenTest": mcas_token_test,
                        "apiUrl": mcas_api,
                    },
                },
                # blocked is { reason: ["ControlId - Name", ...], ... }
                "blockedByMissingAuth": _json_safe(blocked),
                "matchedControlsCount": len(matched_controls or []),
            }

            write_json(preflight_path, preflight_payload)
            print(f"Preflight saved: {preflight_path}")
        except Exception as _e:
            # Never break the run due to evidence writing
            print(f"[WARN] Failed to write auth preflight JSON: {_e}")
    sway_test = None
    try:
        _auth_preflight_summary(tenant, matched)
    except Exception as e:
        print(f"\n[WARN] Auth preflight summary failed: {e}\n")
    # --- end Auth Preflight Summary ---
    # --- Per-control timing (additive) ---
    _CONTROL_TIMINGS = []

    def _record_timing(control_id: str, control_name: str, category: str, tier, mode: str, state: str, reason_code: str, started_at_perf: float):
        try:
            dur = round(time.perf_counter() - started_at_perf, 3)
        except Exception:
            dur = None

        row = {
            "controlId": control_id,
            "name": control_name,
            "category": category,
            "tier": tier,
            "mode": mode,
            "state": state,
            "reasonCode": reason_code,
            "durationSeconds": dur,
        }
        _CONTROL_TIMINGS.append(row)
        return dur
    # --- end timing ---

    tier3_summary = []
    tier3_readiness = {"authMethods": None, "breakGlass": None}

    # --- SPO tenant settings cache (reduces repeated auth popups) ---
    # Cache by admin_url for this run; do NOT persist across runs.
    spo_tenant_settings_cache: dict[str, dict] = {}

    def get_spo_tenant_settings_cached(admin_url: str) -> dict:
        url = (admin_url or '').strip()
        if not url:
            return {"ok": False, "error": "spoAdminUrl missing"}
        if url in spo_tenant_settings_cache:
            return spo_tenant_settings_cache[url]
        res = run_spo_tenant_settings(url)
        spo_tenant_settings_cache[url] = res
        return res
    # --- end SPO cache helper ---
    # --- Teams PowerShell caches (reduces repeated auth + repeated PS calls) ---
    teams_tenant_settings_cache: dict[str, dict] = {}
    teams_meeting_policies_cache: dict[str, dict] = {}

    def _get_teams_ps_auth_from_tenant(tenant: dict) -> tuple[str | None, str | None, str | None]:
        """
        Returns (tenant_id, app_id, thumb) or (None, None, None) if missing.
        We prefer tenant["teamsPowershell"], else tenant["exoPowershell"].
        tenant_id is taken from that block's auth.tenant_id, else tenant.auth.tenant_id.
        """
        ps_cfg = (tenant or {}).get("teamsPowershell") or (tenant or {}).get("exoPowershell") or {}
        auth = (ps_cfg.get("auth") or {})
        tenant_auth = ((tenant or {}).get("auth") or {})

        auth = (ps_cfg.get("auth") or {})
        tenant_auth = ((tenant or {}).get("auth") or {})

        tenant_id = (
            auth.get("tenant_id")
            or auth.get("tenantId")
            or ps_cfg.get("tenant_id")
            or ps_cfg.get("tenantId")
            or tenant_auth.get("tenant_id")
            or tenant_auth.get("tenantId")
        )

        app_id = ps_cfg.get("appId")
        thumb = ps_cfg.get("certificateThumbprint")

        tenant_id = tenant_id.strip() if isinstance(tenant_id, str) else tenant_id
        app_id = app_id.strip() if isinstance(app_id, str) else app_id
        thumb = thumb.strip() if isinstance(thumb, str) else thumb

        return tenant_id, app_id, thumb

    def get_teams_tenant_settings_cached(tenant: dict) -> dict:
        tenant_id, app_id, thumb = _get_teams_ps_auth_from_tenant(tenant)
        if not (tenant_id and app_id and thumb):
            return {"ok": False, "error": "Missing Teams PowerShell auth (tenant_id/appId/certificateThumbprint)"}

        key = f"{tenant_id}|{app_id}|{thumb}"
        if key in teams_tenant_settings_cache:
            return teams_tenant_settings_cache[key]

        res = run_teams_tenant_settings(str(tenant_id), str(app_id), str(thumb))
        teams_tenant_settings_cache[key] = res
        return res

    def get_teams_meeting_policies_cached(tenant: dict) -> dict:
        tenant_id, app_id, thumb = _get_teams_ps_auth_from_tenant(tenant)
        if not (tenant_id and app_id and thumb):
            return {"ok": False, "error": "Missing Teams PowerShell auth (tenant_id/appId/certificateThumbprint)"}

        key = f"{tenant_id}|{app_id}|{thumb}"
        if key in teams_meeting_policies_cache:
            return teams_meeting_policies_cache[key]

        res = run_teams_meeting_policies(str(tenant_id), str(app_id), str(thumb))
        teams_meeting_policies_cache[key] = res
        return res
    # --- end Teams caches ---
    # --- Prewarm Teams meeting policies once per run (keeps per-control timings meaningful) ---
    try:
        _ = get_teams_meeting_policies_cached(tenant)
    except Exception:
        pass
    # --- end Teams prewarm ---
    # --- Prewarm SPO tenant settings once per run (keeps per-control timings meaningful) ---
    try:
        admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
        admin_url = (admin_url or "").strip()
        if admin_url:
            _ = get_spo_tenant_settings_cached(admin_url)
    except Exception:
        pass
    # --- end SPO prewarm ---
    # Prewarm Sway settings auth/call once so Sway controls are cached and cheap
    try:
        from engine.detectors.spo_batch_a import detect_sway_block_external_sharing
        _ = detect_sway_block_external_sharing(tenant, timeout_s=5)
    except Exception:
        pass
    # Prewarm Purview (IPP) bundle once per run so Purview controls are cached and cheap
    try:
        from engine.detectors import mdo as mdo_det
        # Triggers ipp_purview_bundle.ps1 once; if cmdlets are missing, your fast-fail cache will be set.
        _ok, _data = mdo_det._get_purview_bundle(tenant)
    except Exception:
        pass

    for f in matched:
        control_id = f.get("atlasControlId") or f["controlId"]
        control = reg_by_id[control_id]
        _started_at = time.perf_counter()
        _CURRENT_CONTROL_STARTED_AT = _started_at

        # Reset per-control outputs (prevents state/details/reason leaking from previous controls)
        state = "NOT_EVALUATED"
        details = {}
        reason_code = "NOT_EVALUATED"
        reason_detail = "Not evaluated yet."
        f["details"] = {}

        # Determine effective mode (fallback to control default)
        mode = f.get("mode") or control.get("default_mode") or "report-only"

        enforcement_approval_required = bool(control.get("approvalRequired", False) or control.get("tier") in (2, 3) or control_id in ("AdminMFAV2",))


        # Detect-only runs must never require approvals
        detect_only = (str(mode).strip().lower() == "detect-only")

        # Only require approval if it's an enforcement run
        approval_required = enforcement_approval_required and (not detect_only)

        
        approval = None
        approval_payload = None

        # Load approval payload for any control that is enforcement-eligible (tier2/3 or approvalRequired),
        # so approval.mode can override mode even when the tenant is globally report-only.
        if enforcement_approval_required:
            approved, reason, approval_payload = is_control_approved(tenant_name, control_id)

            # Only *block* the run if we are already in enforce mode but approval is missing.
            if str(mode).strip().lower() == "enforce" and not approved:
                print(f"\nSKIP (awaiting approval): {control_id} - {control.get('name','')} ({reason})")

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "ensure_skipped_awaiting_approval",
                    "displayName": control.get("name", control_id),
                    "approved": False,
                    "mode": mode,
                    "status": 403,
                    "reason": reason,
                })
                print(f"Audit saved: {audit_path}")
                continue


        # Normalize approval + mode for ALL controls
        approval = approval_payload
        mode = mode  # keep the effective mode we already computed above
        # If an approval payload specifies a mode, let it override the effective mode for THIS control.
        # This allows per-control enforcement while the tenant remains globally "report-only".
        try:
            if isinstance(approval, dict):
                am = approval.get("mode")
                if am is not None and str(am).strip():
                    mode = str(am).strip()
        except Exception:
            pass

        # Track Tier 3 controls for end-of-run onboarding summary
        tier3_entry = None
        if control.get("tier") == 3:
            tier3_entry = {
                "controlId": control_id,
                "name": control.get("name", control_id),
                "mode": mode,
                "canCauseLockout": bool(control.get("canCauseLockout")),
                "requiresOnboardingDiscussion": bool(control.get("requiresOnboardingDiscussion")),
                "outcome": "NOT_BLOCKED",   # will flip to BLOCKED if Tier 3 gate stops enforcement
                "reason": None,
                "missing": [],
            }
            tier3_summary.append(tier3_entry)

        # --- Tier 3 safety gate: business-impacting controls ---
        if control.get("tier") == 3 and mode == "enforce":
            # Tier 3 controls may NEVER enforce without explicit, fully-acknowledged approval
            if not approval or approval.get("approved") is not True:
                return_not_evaluated(
                    write_audit_event=write_audit_event,
                    tenant_name=tenant_name,
                    control_id=control_id,
                    control=control,
                    mode=mode,
                    approval=approval,
                    reason="Tier 3 control requires an approved approval file to enforce",
                    details={
                        "requiredFields": [
                            "approved:true",
                            "mode:enforce",
                            "acknowledgeLockoutRisk:true",
                            "acknowledgeBusinessImpact:true",
                            "onboardingReviewed:true (if required)",
                        ]
                    },
                )
                continue


            if approval.get("mode") != "enforce":
                return_not_evaluated(
                    write_audit_event=write_audit_event,
                    tenant_name=tenant_name,
                    control_id=control_id,
                    control=control,
                    mode=mode,
                    approval=approval,
                    reason="Tier 3 control not enforced: approval mode is not enforce",
                    details={"approvalMode": approval.get("mode")},
                )

                continue

            # Consolidated Tier 3 required acknowledgements (single block with explicit missing fields)
            missing = []

            if approval.get("acknowledgeLockoutRisk") is not True:
                missing.append("acknowledgeLockoutRisk:true")

            if approval.get("acknowledgeBusinessImpact") is not True:
                missing.append("acknowledgeBusinessImpact:true")

            if control.get("requiresOnboardingDiscussion") and approval.get("onboardingReviewed") is not True:
                missing.append("onboardingReviewed:true")
            
            if missing:
                if tier3_entry is not None:
                    tier3_entry["outcome"] = "BLOCKED"
                    tier3_entry["reason"] = "missing required acknowledgements"
                    tier3_entry["missing"] = missing
                
                return_not_evaluated(
                    write_audit_event=write_audit_event,
                    tenant_name=tenant_name,
                    control_id=control_id,
                    control=control,
                    mode=mode,
                    approval=approval,
                    reason="Tier 3 control not enforced: missing required acknowledgements",
                    details={
                        "missing": missing,
                        "hint": "Complete Tier 3 acknowledgements to view technical readiness requirements."
                    },
                )


                continue
            # --- Tier 3 readiness gate (soft preconditions) ---
            # We do NOT rely on control ordering. If readiness hasn't been evaluated yet in this run,
            # we evaluate it here (detect-only) before allowing enforcement.

            # Ensure readiness store exists (in case file is edited/reordered)
            try:
                tier3_readiness
            except NameError:
                tier3_readiness = {"authMethods": None, "breakGlass": None}

            # Helper to set readiness state
            def _set_ready(key: str, state: str):
                if state == "COMPLIANT":
                    tier3_readiness[key] = "READY"
                elif state == "DRIFTED":
                    tier3_readiness[key] = "NOT_READY"
                else:
                    tier3_readiness[key] = "ERROR"

            # Evaluate readiness on-demand
            if control_id in ("CAAdminPhishingResistantMFA",) and tier3_readiness.get("authMethods") is None:
                from engine.detectors.entra import detect_tier3_auth_methods_readiness
                r_state, r_details = detect_tier3_auth_methods_readiness(tenant)
                _set_ready("authMethods", r_state)

            if control_id in ("CAAdminPhishingResistantMFA", "CAAdminSignInFrequencySessionTimeout") and tier3_readiness.get("breakGlass") is None:
                from engine.detectors.entra import detect_tier3_break_glass_readiness
                r_state, r_details = detect_tier3_break_glass_readiness(tenant)
                _set_ready("breakGlass", r_state)

            # Now enforce readiness requirements per control
            missing_ready = []
            auth_ready = tier3_readiness.get("authMethods")
            bg_ready = tier3_readiness.get("breakGlass")

            if control_id == "CAAdminPhishingResistantMFA":
                if auth_ready != "READY":
                    missing_ready.append(f"AuthMethods:{auth_ready or 'UNKNOWN'}")
                if bg_ready != "READY":
                    missing_ready.append(f"BreakGlass:{bg_ready or 'UNKNOWN'}")

            if control_id == "CAAdminSignInFrequencySessionTimeout":
                if bg_ready != "READY":
                    missing_ready.append(f"BreakGlass:{bg_ready or 'UNKNOWN'}")

            if missing_ready:
                if tier3_entry is not None:
                    tier3_entry["outcome"] = "BLOCKED"
                    tier3_entry["reason"] = "readiness NOT_READY"
                    tier3_entry["missing"] = missing_ready
                # Build explicit customer-facing next steps for readiness failures
                next_steps = []

                # Auth methods readiness (phishing-resistant)
                if control_id == "CAAdminPhishingResistantMFA":
                    if auth_ready != "READY":
                        next_steps.append("Enable FIDO2 and/or Windows Hello for Business in Entra Authentication Methods Policy before enforcing phishing-resistant MFA for admins.")
                    if bg_ready != "READY":
                        next_steps.append("Fix break-glass readiness: ensure the break-glass group contains at least two enabled user accounts (and that Atlas excludes the group from its CA policies).")

                # Session control readiness (business continuity)
                if control_id == "CAAdminSignInFrequencySessionTimeout":
                    if bg_ready != "READY":
                        next_steps.append("Fix break-glass readiness: ensure the break-glass group contains at least two enabled user accounts before enforcing sign-in frequency/session controls for admins.")
                return_not_evaluated(
                    write_audit_event=_write_audit_event_timed,
                    tenant_name=tenant_name,
                    control_id=control_id,
                    control=control,
                    mode=mode,
                    approval=approval,
                    reason="Tier 3 control not enforced: readiness prerequisites not met",
                    details={
                        "missingReadiness": missing_ready,
                        "readiness": tier3_readiness,
                        "nextSteps": next_steps
                    },
                )

                continue

        if detect_only:
            run_type = "detect-only"
        elif approval_required:
            run_type = "approved"
        else:
            run_type = "auto"

        print(f"\nRUN ({run_type}): {control_id} - {control.get('name','')}")
        # =========================
        # Enforcer Registry Dispatch (additive)
        # =========================
        try:
            from engine.enforcement.registry import get_enforcer
            enforcer = get_enforcer(control_id)
        except Exception:
            enforcer = None

        if enforcer:
            # Registry enforcers may support enforcement even for Tier-1 controls.
            # Load approval on-demand so approval.mode can override detect-only defaults.
            if approval is None:
                try:
                    _approved, _reason, _approval_payload = is_control_approved(tenant_name, control_id)
                    if isinstance(_approval_payload, dict):
                        approval = _approval_payload
                except Exception:
                    pass
            # Compute effective mode AFTER approval resolution
            mode_eff = (approval.get("mode") if approval else control.get("default_mode") or "report-only")
            # Enforce gating remains the same: if mode is enforce but no approval, block.
            if mode_eff == "enforce" and not approval:
                return_not_evaluated(
                    write_audit_event=_write_audit_event_timed,
                    tenant_name=tenant_name,
                    control_id=control_id,
                    control=control,
                    mode=mode_eff,
                    approval=approval,
                    reason="Enforcement blocked: missing approval file",
                    details={"reasonCode": "APPROVAL_REQUIRED", "reasonDetail": "No approvals/<tenant>/<control>.json present"},
                )

                continue
            print(f"[DEBUG] registry approval resolved: control={control_id} approved={bool(approval)} mode_eff={mode_eff}")

            state, reason_code, reason_detail, details, status = enforcer(
                tenant=tenant,
                tenant_name=tenant_name,
                control=control,
                control_id=control_id,
                headers=headers,
                approval=approval,
                mode=mode_eff,
            )
            # Evidence hardening: ensure details.before/desired/after use the actual control_id as key
            if isinstance(details, dict):
                for k in ("before", "desired", "after"):
                    if isinstance(details.get(k), dict):
                        if len(details[k]) == 1 and control_id not in details[k]:
                            only_key = next(iter(details[k].keys()))
                            details[k] = {control_id: details[k].get(only_key)}

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "ensure_applied" if mode_eff == "enforce" else "detect_report_only",
                "displayName": control.get("name", control_id),
                "approved": bool(approval),
                "mode": mode_eff,
                "state": state,
                "reasonCode": reason_code,
                "reasonDetail": reason_detail,
                "details": details or {},
                "status": int(status) if status is not None else 200,
            })

            print(f"{'ENFORCER' if mode_eff == 'enforce' else 'REPORT'}: {control_id} | state={state} | {reason_code}")
            print(f"Audit saved: {audit_path}")
            continue


        if control_id == "SigninRiskPolicy":
            mode = (approval.get("mode") if approval else control.get("default_mode") or "report-only")

            payload = build_rs_payload(mode=mode)

            result = ensure_policy(
                headers=headers,
                display_name=RS_DISPLAY_NAME,
                payload=payload,
                allow_update=True
            )

            print(f"{result['result'].upper()}: {RS_DISPLAY_NAME} | {result['policyId']} | status={result['status']}")

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": f"ensure_{result['result']}",
                "displayName": RS_DISPLAY_NAME,
                "approved": bool(approval),
                "mode": mode,
                "status": result["status"],
                "policyId": result["policyId"],
            })

            print(f"Audit saved: {audit_path}")


        elif control_id == "UserRiskPolicy":
            mode = approval.get("mode") if approval else control.get("default_mode", "report-only")
            payload = build_rup_payload(mode=mode)

            result = ensure_policy(headers, RUP_DISPLAY_NAME, payload, allow_update=True)
            print(f"{result['result'].upper()}: {RUP_DISPLAY_NAME} | {result['policyId']} | status={result['status']}")

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": f"ensure_{result['result']}",
                "displayName": RUP_DISPLAY_NAME,
                "approved": bool(approval),
                "mode": mode,
                "status": result["status"],
                "policyId": result["policyId"],
            })
            print(f"Audit saved: {audit_path}")


        elif control_id == "AdminMFAV2":
            mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))
            payload = build_am_payload(mode=mode)
            result = ensure_policy(headers, payload["displayName"], payload, allow_update=True)
            print(f"{result['result'].upper()}: {payload['displayName']} | {result['policyId']} | status={result['status']}")

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": f"ensure_{result['result']}",
                "displayName": payload['displayName'],
                "approved": bool(approval),
                "mode": mode,
                "state": ("COMPLIANT" if mode == "enforce" and result.get("status") in (200, 201) else "NOT_EVALUATED"),
                "status": result["status"],
                "policyId": result["policyId"],
            })
            print(f"Audit saved: {audit_path}")
        elif control_id == "SharePointPreventExternalUsersFromResharingEnabled":
            # Detect-only: rely on existing SPO fallback evaluation in the generic detect-only path
            # (Do not enforce here.)
            if detect_only:
                # Let it flow to the generic detect-only block below
                pass
            else:
                # report-only/enforce path
                from engine.enforcement.spo import apply_spo_prevent_external_users_from_resharing

                admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                admin_url = (admin_url or "").strip()

                mode_eff = (approval.get("mode") if approval else control.get("default_mode", "report-only"))

                state, details = apply_spo_prevent_external_users_from_resharing(
                    admin_url=admin_url,
                    mode=mode_eff,
                )

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": (
                        "ensure_applied"
                        if state == "UPDATED"
                        else "ensure_skipped_no_drift"
                        if state == "COMPLIANT"
                        else "ensure_not_evaluated"
                        if state == "NOT_EVALUATED"
                        else "ensure_error"
                    ),
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode_eff,
                    "status": 200 if state in ("COMPLIANT", "UPDATED", "DRIFTED") else 500,
                    "details": details,
                    "reason": "SPO PowerShell enforcement: PreventExternalUsersFromResharing",
                })

                label = "REPORT-ONLY" if mode_eff == "report-only" else "ENFORCE"
                if state == "NOT_EVALUATED":
                    label = "SKIPPED_NOT_EVALUATED"
                print(f"{label}: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue
        elif (not detect_only) and control_id == "SharePointDomainRestrictionConfigured":
            if detect_only:
                # Let it flow to the generic detect-only SPO tenant-settings evaluator below
                pass
            else:

                from engine.detectors.spo import set_spo_domain_restriction

                admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                admin_url = (admin_url or "").strip()

                mode_eff = (approval.get("mode") if approval else control.get("default_mode", "report-only"))

                # Enforcement parameters must be explicitly supplied (never guess domains)
                params = (approval_payload or {}).get("parameters") or {}
                desired_mode = (params.get("sharingDomainRestrictionMode") or "").strip()  # AllowList|BlockList
                allowed_domains = params.get("sharingAllowedDomainList")
                blocked_domains = params.get("sharingBlockedDomainList")

                if not admin_url:
                    state = "NOT_EVALUATED"
                    reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                    reason_detail = "spoAdminUrl not set; cannot connect to SPO service"
                    details = {"missingKeys": ["spoAdminUrl"]}
                else:
                    pre = run_spo_tenant_settings(admin_url)
                    if not pre.get("ok"):
                        state = "NOT_EVALUATED"
                        reason_code = "FALLBACK_DETECTOR_ERROR"
                        reason_detail = f"SPO read failed: {pre.get('error')}"
                        details = {"stage": "read_before", "error": pre.get("error"), "raw": pre.get("raw"), "stderr": pre.get("stderr")}
                    else:
                        t = pre.get("tenant") or {}
                        cur = t.get("SharingDomainRestrictionMode")
                        cur_norm = None if cur is None else str(cur).strip()

                        details = {
                            "before": cur,
                            "before_normalized": cur_norm,
                            "mode": mode_eff,
                            "requested": {
                                "sharingDomainRestrictionMode": desired_mode or None,
                                "sharingAllowedDomainList": allowed_domains,
                                "sharingBlockedDomainList": blocked_domains,
                            }
                        }

                        if mode_eff == "report-only":
                            # COMPLIANT if mode is set to a non-empty, non-"0/none" value
                            if cur_norm and cur_norm.lower() not in ("none", "0"):
                                state = "COMPLIANT"
                            else:
                                state = "DRIFTED"
                            reason_code = "REPORT_ONLY_EVALUATED"
                            reason_detail = "Report-only: evaluated SPO domain restriction mode; no changes applied"

                        elif mode_eff == "enforce":
                            missing = []
                            if desired_mode not in ("AllowList", "BlockList"):
                                missing.append("parameters.sharingDomainRestrictionMode (AllowList|BlockList)")
                            if desired_mode == "AllowList" and (not allowed_domains or not str(allowed_domains).strip()):
                                missing.append("parameters.sharingAllowedDomainList")
                            if desired_mode == "BlockList" and (not blocked_domains or not str(blocked_domains).strip()):
                                missing.append("parameters.sharingBlockedDomainList")

                            if missing:
                                state = "NOT_EVALUATED"
                                reason_code = "MISSING_ENFORCEMENT_PARAMETERS"
                                reason_detail = "Enforce requested but required domain restriction parameters were not provided"
                                details["missingKeys"] = missing
                            else:
                                set_result = set_spo_domain_restriction(
                                    admin_url=admin_url,
                                    mode=desired_mode,
                                    allowed_domains=str(allowed_domains or ""),
                                    blocked_domains=str(blocked_domains or ""),
                                )
                                details["applyResult"] = set_result

                                if not set_result.get("ok"):
                                    state = "ERROR"
                                    reason_code = "ENFORCER_ERROR"
                                    reason_detail = f"Failed to apply SPO domain restriction: {set_result.get('error')}"
                                else:
                                    post = run_spo_tenant_settings(admin_url)
                                    details["afterRead"] = post

                                    if not post.get("ok"):
                                        state = "ERROR"
                                        reason_code = "ENFORCER_ERROR"
                                        reason_detail = f"Applied but failed re-check: {post.get('error')}"
                                    else:
                                        new_val = (post.get("tenant") or {}).get("SharingDomainRestrictionMode")
                                        new_norm = None if new_val is None else str(new_val).strip()
                                        details["after"] = new_val
                                        details["after_normalized"] = new_norm

                                        if new_norm and new_norm.lower() not in ("none", "0"):
                                            state = "UPDATED"
                                            reason_code = "ENFORCED"
                                            reason_detail = "Applied SPO domain restriction and verified"
                                        else:
                                            state = "ERROR"
                                            reason_code = "ENFORCER_ERROR"
                                            reason_detail = "Apply succeeded but restriction mode still appears unset"

                        else:
                            state = "NOT_EVALUATED"
                            reason_code = "UNSUPPORTED_MODE"
                            reason_detail = f"Unsupported mode: {mode_eff}"

            audit_path = _write_audit_event_timed(
                tenant_name,
                attach_reason({
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": (
                        "ensure_applied" if state == "UPDATED"
                        else "ensure_skipped_no_drift" if state == "COMPLIANT"
                        else "ensure_not_evaluated" if state == "NOT_EVALUATED"
                        else "ensure_error"
                    ),
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode_eff,
                    "status": 200 if state in ("COMPLIANT", "UPDATED", "DRIFTED") else 500,
                    "details": details,
                }, reason_code, reason_detail)
            )

            label = "REPORT-ONLY" if mode_eff == "report-only" else "ENFORCE"
            if state == "NOT_EVALUATED":
                label = "SKIPPED_NOT_EVALUATED"
            print(f"{label}: {control_id} | state={state}")
            print(f"Audit saved: {audit_path}")
            continue

        
        elif (not detect_only) and control_id == "SharePointSharingAllowedDomainListConfigured":
            if detect_only:
                pass
            else:
                # existing enforcement logic...

                from engine.detectors.spo import set_spo_domain_restriction

                admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                admin_url = (admin_url or "").strip()

                mode_eff = (approval.get("mode") if approval else control.get("default_mode", "report-only"))

                # Required enforcement parameter (never guess domains)
                params = (approval_payload or {}).get("parameters") or {}
                allowed_domains = params.get("sharingAllowedDomainList")

                def _norm_mode(v):
                    if v is None:
                        return None
                    s = str(v).strip()
                    if s.isdigit():
                        return {"0": "None", "1": "AllowList", "2": "BlockList"}.get(s, s)
                    return s

                if not admin_url:
                    state = "NOT_EVALUATED"
                    reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                    reason_detail = "spoAdminUrl not set; cannot connect to SPO service"
                    details = {"missingKeys": ["spoAdminUrl"]}
                else:
                    pre = run_spo_tenant_settings(admin_url)
                    if not pre.get("ok"):
                        state = "NOT_EVALUATED"
                        reason_code = "FALLBACK_DETECTOR_ERROR"
                        reason_detail = f"SPO read failed: {pre.get('error')}"
                        details = {"stage": "read_before", "error": pre.get("error"), "raw": pre.get("raw"), "stderr": pre.get("stderr")}
                    else:
                        t = pre.get("tenant") or {}
                        cur_mode = _norm_mode(t.get("SharingDomainRestrictionMode"))
                        cur_allowed = t.get("SharingAllowedDomainList")

                        # Normalize allowed domains
                        allowed_str = "" if cur_allowed is None else str(cur_allowed).strip()
                        parts = [p.strip() for p in allowed_str.replace(";", ",").replace("\n", ",").split(",")]
                        cur_allowed_norm = [p for p in parts if p]

                        details = {
                            "before": {
                                "SharingDomainRestrictionMode": t.get("SharingDomainRestrictionMode"),
                                "SharingAllowedDomainList": cur_allowed,
                            },
                            "before_normalized": {
                                "SharingDomainRestrictionMode": cur_mode,
                                "SharingAllowedDomainList": cur_allowed_norm,
                            },
                            "mode": mode_eff,
                            "requested": {"sharingAllowedDomainList": allowed_domains},
                        }

                        if mode_eff == "report-only":
                            if cur_mode != "AllowList":
                                state = "DRIFTED"
                            else:
                                state = "COMPLIANT" if len(cur_allowed_norm) > 0 else "DRIFTED"
                            reason_code = "REPORT_ONLY_EVALUATED"
                            reason_detail = "Report-only: evaluated SPO allowed domain list posture; no changes applied"

                        elif mode_eff == "enforce":
                            if not allowed_domains or not str(allowed_domains).strip():
                                state = "NOT_EVALUATED"
                                reason_code = "MISSING_ENFORCEMENT_PARAMETERS"
                                reason_detail = "Enforce requested but parameters.sharingAllowedDomainList was not provided"
                                details["missingKeys"] = ["parameters.sharingAllowedDomainList"]
                            else:
                                set_result = set_spo_domain_restriction(
                                    admin_url=admin_url,
                                    mode="AllowList",
                                    allowed_domains=str(allowed_domains).strip(),
                                    blocked_domains="",
                                )
                                details["applyResult"] = set_result

                                if not set_result.get("ok"):
                                    state = "ERROR"
                                    reason_code = "ENFORCER_ERROR"
                                    reason_detail = f"Failed to apply SPO AllowList: {set_result.get('error')}"
                                else:
                                    post = run_spo_tenant_settings(admin_url)
                                    details["afterRead"] = post

                                    if not post.get("ok"):
                                        state = "ERROR"
                                        reason_code = "ENFORCER_ERROR"
                                        reason_detail = f"Applied but failed re-check: {post.get('error')}"
                                    else:
                                        tt = post.get("tenant") or {}
                                        new_mode = _norm_mode(tt.get("SharingDomainRestrictionMode"))
                                        new_allowed = tt.get("SharingAllowedDomainList")
                                        new_allowed_str = "" if new_allowed is None else str(new_allowed).strip()
                                        parts2 = [p.strip() for p in new_allowed_str.replace(";", ",").replace("\n", ",").split(",")]
                                        new_allowed_norm = [p for p in parts2 if p]

                                        details["after"] = {
                                            "SharingDomainRestrictionMode": tt.get("SharingDomainRestrictionMode"),
                                            "SharingAllowedDomainList": new_allowed,
                                        }
                                        details["after_normalized"] = {
                                            "SharingDomainRestrictionMode": new_mode,
                                            "SharingAllowedDomainList": new_allowed_norm,
                                        }

                                        if new_mode == "AllowList" and len(new_allowed_norm) > 0:
                                            state = "UPDATED"
                                            reason_code = "ENFORCED"
                                            reason_detail = "Applied SPO AllowList and verified"
                                        else:
                                            state = "ERROR"
                                            reason_code = "ENFORCER_ERROR"
                                            reason_detail = "Apply succeeded but desired AllowList posture not observed"

                        else:
                            state = "NOT_EVALUATED"
                            reason_code = "UNSUPPORTED_MODE"
                            reason_detail = f"Unsupported mode: {mode_eff}"

            audit_path = _write_audit_event_timed(
                tenant_name,
                attach_reason({
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": (
                        "ensure_applied" if state == "UPDATED"
                        else "ensure_skipped_no_drift" if state == "COMPLIANT"
                        else "ensure_not_evaluated" if state == "NOT_EVALUATED"
                        else "ensure_error"
                    ),
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "approved": True if approval_required else False,
                    "mode": mode_eff,
                    "status": 200 if state in ("COMPLIANT", "UPDATED", "DRIFTED") else 500,
                    "details": details,
                }, reason_code, reason_detail)
            )

            label = "REPORT-ONLY" if mode_eff == "report-only" else "ENFORCE"
            if state == "NOT_EVALUATED":
                label = "SKIPPED_NOT_EVALUATED"
            print(f"{label}: {control_id} | state={state}")
            print(f"Audit saved: {audit_path}")
            continue

        elif (not detect_only) and control_id == "SharePointSharingBlockedDomainListConfigured":
            if detect_only:
                pass
            else:
                # existing enforcement logic...

                from engine.detectors.spo import set_spo_domain_restriction

                admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                admin_url = (admin_url or "").strip()

                mode_eff = (approval.get("mode") if approval else control.get("default_mode", "report-only"))

                # Required enforcement parameter (never guess domains)
                params = (approval_payload or {}).get("parameters") or {}
                blocked_domains = params.get("sharingBlockedDomainList")

                def _norm_mode(v):
                    if v is None:
                        return None
                    s = str(v).strip()
                    if s.isdigit():
                        return {"0": "None", "1": "AllowList", "2": "BlockList"}.get(s, s)
                    return s

                if not admin_url:
                    state = "NOT_EVALUATED"
                    reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                    reason_detail = "spoAdminUrl not set; cannot connect to SPO service"
                    details = {"missingKeys": ["spoAdminUrl"]}
                else:
                    pre = run_spo_tenant_settings(admin_url)
                    if not pre.get("ok"):
                        state = "NOT_EVALUATED"
                        reason_code = "FALLBACK_DETECTOR_ERROR"
                        reason_detail = f"SPO read failed: {pre.get('error')}"
                        details = {"stage": "read_before", "error": pre.get("error"), "raw": pre.get("raw"), "stderr": pre.get("stderr")}
                    else:
                        t = pre.get("tenant") or {}
                        cur_mode = _norm_mode(t.get("SharingDomainRestrictionMode"))
                        cur_blocked = t.get("SharingBlockedDomainList")

                        blocked_str = "" if cur_blocked is None else str(cur_blocked).strip()
                        parts = [p.strip() for p in blocked_str.replace(";", ",").replace("\n", ",").split(",")]
                        cur_blocked_norm = [p for p in parts if p]

                        details = {
                            "before": {
                                "SharingDomainRestrictionMode": t.get("SharingDomainRestrictionMode"),
                                "SharingBlockedDomainList": cur_blocked,
                            },
                            "before_normalized": {
                                "SharingDomainRestrictionMode": cur_mode,
                                "SharingBlockedDomainList": cur_blocked_norm,
                            },
                            "mode": mode_eff,
                            "requested": {"sharingBlockedDomainList": blocked_domains},
                        }

                        if mode_eff == "report-only":
                            if cur_mode != "BlockList":
                                state = "DRIFTED"
                            else:
                                state = "COMPLIANT" if len(cur_blocked_norm) > 0 else "DRIFTED"
                            reason_code = "REPORT_ONLY_EVALUATED"
                            reason_detail = "Report-only: evaluated SPO blocked domain list posture; no changes applied"

                        elif mode_eff == "enforce":
                            if not blocked_domains or not str(blocked_domains).strip():
                                state = "NOT_EVALUATED"
                                reason_code = "MISSING_ENFORCEMENT_PARAMETERS"
                                reason_detail = "Enforce requested but parameters.sharingBlockedDomainList was not provided"
                                details["missingKeys"] = ["parameters.sharingBlockedDomainList"]
                            else:
                                set_result = set_spo_domain_restriction(
                                    admin_url=admin_url,
                                    mode="BlockList",
                                    allowed_domains="",
                                    blocked_domains=str(blocked_domains).strip(),
                                )
                                details["applyResult"] = set_result

                                if not set_result.get("ok"):
                                    state = "ERROR"
                                    reason_code = "ENFORCER_ERROR"
                                    reason_detail = f"Failed to apply SPO BlockList: {set_result.get('error')}"
                                else:
                                    post = run_spo_tenant_settings(admin_url)
                                    details["afterRead"] = post

                                    if not post.get("ok"):
                                        state = "ERROR"
                                        reason_code = "ENFORCER_ERROR"
                                        reason_detail = f"Applied but failed re-check: {post.get('error')}"
                                    else:
                                        tt = post.get("tenant") or {}
                                        new_mode = _norm_mode(tt.get("SharingDomainRestrictionMode"))
                                        new_blocked = tt.get("SharingBlockedDomainList")
                                        new_blocked_str = "" if new_blocked is None else str(new_blocked).strip()
                                        parts2 = [p.strip() for p in new_blocked_str.replace(";", ",").replace("\n", ",").split(",")]
                                        new_blocked_norm = [p for p in parts2 if p]

                                        details["after"] = {
                                            "SharingDomainRestrictionMode": tt.get("SharingDomainRestrictionMode"),
                                            "SharingBlockedDomainList": new_blocked,
                                        }
                                        details["after_normalized"] = {
                                            "SharingDomainRestrictionMode": new_mode,
                                            "SharingBlockedDomainList": new_blocked_norm,
                                        }

                                        if new_mode == "BlockList" and len(new_blocked_norm) > 0:
                                            state = "UPDATED"
                                            reason_code = "ENFORCED"
                                            reason_detail = "Applied SPO BlockList and verified"
                                        else:
                                            state = "ERROR"
                                            reason_code = "ENFORCER_ERROR"
                                            reason_detail = "Apply succeeded but desired BlockList posture not observed"

                        else:
                            state = "NOT_EVALUATED"
                            reason_code = "UNSUPPORTED_MODE"
                            reason_detail = f"Unsupported mode: {mode_eff}"

            audit_path = _write_audit_event_timed(
                tenant_name,
                attach_reason({
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": (
                        "ensure_applied" if state == "UPDATED"
                        else "ensure_skipped_no_drift" if state == "COMPLIANT"
                        else "ensure_not_evaluated" if state == "NOT_EVALUATED"
                        else "ensure_error"
                    ),
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "approved": True if approval_required else False,
                    "mode": mode_eff,
                    "status": 200 if state in ("COMPLIANT", "UPDATED", "DRIFTED") else 500,
                    "details": details,
                }, reason_code, reason_detail)
            )

            label = "REPORT-ONLY" if mode_eff == "report-only" else "ENFORCE"
            if state == "NOT_EVALUATED":
                label = "SKIPPED_NOT_EVALUATED"
            print(f"{label}: {control_id} | state={state}")
            print(f"Audit saved: {audit_path}")
            continue

        elif control_id == "BlockLegacyAuthenticationPolicy":
                    # NOTE: report-only must NOT create/update. It may only detect drift.
                    from engine.enforcement.policies.block_legacy_auth import (
                        DISPLAY_NAME as BLA_DISPLAY_NAME,
                        build_payload as build_bla_payload
                    )

                    mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))
                    desired = build_bla_payload(mode=mode)

                    existing, ca_debug = get_ca_policy_by_display_name(headers, BLA_DISPLAY_NAME)

                    if mode == "report-only":
                        # If report-only: no create/update. Detect-only behavior for this enforcement control.
                        if not existing:
                            # Graph cannot see all CA policies in app-only context.
                            # Only mark COMPLIANT if the posture signal says legacy auth is blocked.
                            # Pull the Secure Score signal from the *status* control (not from this enforcement control)
                            status_ctrl = reg_by_id.get("BlockLegacyAuthenticationStatus", {})
                            linked = status_ctrl.get("secureScoreControlIds") or []

                            scores = []
                            for ssid in linked:
                                ff = findings_by_ssid.get(ssid)
                                if ff and ff.get("scorePct") is not None:
                                    try:
                                        scores.append(float(ff["scorePct"]))
                                    except Exception:
                                        pass
                                else:
                                    # Missing finding => conservative drift
                                    scores.append(0.0)

                            pct = min(scores) if scores else None


                            if pct is not None and pct >= 100:
                                state = "COMPLIANT"
                                details = {
                                    "reason": "Policy not visible via Graph app-only; legacy auth confirmed blocked via Secure Score signal",
                                    "displayName": BLA_DISPLAY_NAME,
                                    "scorePct": pct,
                                    "caDebug": ca_debug,
                                    }
                            else:
                                state = "DRIFTED"
                                details = {
                                    "reason": "Policy not visible via Graph app-only; legacy auth not fully blocked per Secure Score signal",
                                    "displayName": BLA_DISPLAY_NAME,
                                    "scorePct": pct,
                                    "caDebug": ca_debug,
                                }

                        else:
                            # Compare by normalising state to enabledForReportingButNotEnforced expectation
                            # and comparing the rest of payload fields we control.
                            # (Keep comparison minimal to avoid Graph adding fields.)
                            def _norm_list(x):
                                return sorted(list(x or []))

                            def _get(d: dict, path: list, default=None):
                                cur = d
                                for p in path:
                                    if not isinstance(cur, dict):
                                        return default
                                    cur = cur.get(p)
                                return cur if cur is not None else default

                            def is_equivalent_block_legacy(existing: dict, desired: dict) -> bool:
                                if existing.get("displayName") != desired.get("displayName"):
                                    return False

                                # In report-only we accept either "enabled" or "enabledForReportingButNotEnforced"
                                # because report-only should not fail posture purely due to CA state semantics.
                                ex_state = (existing.get("state") or "").strip()
                                if ex_state not in ("enabled", "enabledForReportingButNotEnforced"):
                                    return False


                                if _norm_list(_get(existing, ["conditions", "clientAppTypes"])) != \
                                _norm_list(_get(desired, ["conditions", "clientAppTypes"])):
                                    return False

                                if _norm_list(_get(existing, ["conditions", "applications", "includeApplications"])) != \
                                _norm_list(_get(desired, ["conditions", "applications", "includeApplications"])):
                                    return False

                                if _norm_list(_get(existing, ["conditions", "users", "includeUsers"])) != \
                                _norm_list(_get(desired, ["conditions", "users", "includeUsers"])):
                                    return False

                                if _norm_list(_get(existing, ["grantControls", "builtInControls"])) != \
                                _norm_list(_get(desired, ["grantControls", "builtInControls"])):
                                    return False

                                return True

                            is_match = is_equivalent_block_legacy(existing, desired)

                            state = "COMPLIANT" if is_match else "DRIFTED"
                            details = {
                                "policyId": existing.get("id"),
                                "match": is_match,
                                "reason": "Matches desired payload" if is_match else "Policy differs from desired payload",
                            }

                        audit_path = _write_audit_event_timed(tenant_name, {
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "ensure_report_only_check",
                            "state": state,
                            "displayName": BLA_DISPLAY_NAME,
                            "approved": bool(approval),
                            "mode": mode,
                            "status": 200,
                            "details": details,
                        })
                        print(f"REPORT-ONLY: {control_id} | state={state}")
                        print(f"Audit saved: {audit_path}")
                        continue

                    # Enforce mode: create/update allowed (existing ensure_policy path)
                    payload = desired
                    result = ensure_policy(headers, BLA_DISPLAY_NAME, payload, allow_update=True)
                    print(f"{result['result'].upper()}: {BLA_DISPLAY_NAME} | {result['policyId']} | status={result['status']}")

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": f"ensure_{result['result']}",
                        "displayName": BLA_DISPLAY_NAME,
                        "approved": bool(approval),
                        "mode": mode,
                        "status": result["status"],
                        "policyId": result["policyId"],
                    })
        elif control_id == "BlockLegacyAuthenticationStatus":
            DISPLAY = control.get("name", control_id)

            sec_defaults = get_security_defaults_status(headers)
            if sec_defaults is None:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect",
                    "state": "NOT_EVALUATED",
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": "detect-only",
                    "status": 500,
                    "details": {
                        "missingKeys": ["securityDefaultsStatus"],
                        "note": "Unable to read Security Defaults status via Graph.",
                    },
                    "reason": "Graph read failed for Security Defaults policy",
                })
                print(f"NOT_EVALUATED: {control_id} | unable to read Security Defaults")
                print(f"Audit saved: {audit_path}")
                continue

            # If Security Defaults is enabled, CA cannot be managed and baseline protections apply.
            if sec_defaults is True:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect",
                    "state": "COMPLIANT",
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": "detect-only",
                    "status": 200,
                    "details": {
                        "securityDefaultsEnabled": True,
                        "note": "Security Defaults enabled; Conditional Access evaluation is not applicable for this posture check.",
                    },
                    "reason": "Security Defaults enabled",
                })
                print(f"COMPLIANT: {control_id} | Security Defaults enabled")
                print(f"Audit saved: {audit_path}")
                continue

            legacy_block = find_legacy_auth_blocking_policy(headers)

            if legacy_block.get("found") is True:
                state = "COMPLIANT" if legacy_block.get("enabled") else "DRIFTED"
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect",
                    "state": state,
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": "detect-only",
                    "status": 200,
                    "details": {
                        "securityDefaultsEnabled": False,
                        "policy": legacy_block,
                    },
                    "reason": "Conditional Access legacy auth block policy evaluated",
                })
                print(f"{state}: {control_id} | CA legacy auth block policy evaluated")
                print(f"Audit saved: {audit_path}")
                continue

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "detect",
                "state": "NOT_EVALUATED",
                "displayName": DISPLAY,
                "approved": bool(approval),
                "mode": "detect-only",
                "status": 424,
                "details": {
                    "missingKeys": ["conditionalAccessPolicyBlockingLegacyAuth"],
                    "securityDefaultsEnabled": False,
                    "note": "No CA policy found with grantControls=block and clientAppTypes including exchangeActiveSync/other.",
                },
                "reason": "Missing CA policy that blocks legacy authentication",
            })
            print(f"NOT_EVALUATED: {control_id} | no CA legacy auth block policy found")
            print(f"Audit saved: {audit_path}")
            continue
           
        elif control_id == "CAAdminBlockLegacyAuth":
            from engine.enforcement.policies.ca_admin_block_legacy_auth import (
                DISPLAY_NAME as DISPLAY,
                build_payload as build_payload,
            )

            mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))
            blocked, safety_details = safety_block_if_no_break_glass(
                control_id=control_id,
                mode=mode,
                approval=approval,
                tenant=tenant,
            )

            if blocked:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "ensure_safety_blocked",
                    "state": "NOT_EVALUATED",
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 409,
                    "details": safety_details,
                    "reason": "Atlas safety gate: prevent tenant lockout",
                })
                reason = None
                if isinstance(safety_details, dict):
                    reason = safety_details.get("reason") or safety_details.get("blockReason")
                if not reason:
                    reason = "Atlas safety gate: prevent tenant lockout (see audit details)"
                print(f"SAFETY_BLOCK: {control_id} | state=NOT_EVALUATED | reason={reason}")

                print(f"Audit saved: {audit_path}")
                continue

            desired = build_payload(mode=mode, exclude_group_id=get_break_glass_group_id(tenant))


            existing, ca_debug = get_ca_policy_by_display_name(headers, DISPLAY)

            if mode == "report-only":
                if not existing:
                    state = "DRIFTED"
                    details = {"reason": "Policy missing (report-only; not creating)", "displayName": DISPLAY}
                else:
                    def _pick(p: dict) -> dict:
                        conditions = (p.get("conditions") or {})
                        users = (conditions.get("users") or {})
                        apps = (conditions.get("applications") or {})
                        return {
                            "state": p.get("state"),
                            "clientAppTypes": conditions.get("clientAppTypes"),
                            "includeUsers": users.get("includeUsers"),
                            "excludeUsers": users.get("excludeUsers"),
                            "includeApplications": apps.get("includeApplications"),
                            "excludeApplications": apps.get("excludeApplications"),
                            "grantControls": p.get("grantControls"),
                        }

                    if _pick(existing) == _pick(desired):
                        state = "COMPLIANT"
                        details = {"reason": "Matches desired (report-only)", "displayName": DISPLAY}
                    else:
                        state = "DRIFTED"
                        details = {
                            "reason": "Drift detected (report-only; not updating)",
                            "displayName": DISPLAY,
                            "desiredSubset": _pick(desired),
                            "existingSubset": _pick(existing),
                        }
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_report_only",
                    "displayName": DISPLAY,
                    "state": ("COMPLIANT" if int(result.get("status") or 0) < 400 else "NOT_EVALUATED"),
                    "reasonCode": ("ENFORCER_EXECUTED" if int(result.get("status") or 0) < 400 else "ENFORCER_ERROR"),
                    "approved": bool(approval),
                    "mode": mode,
                    "details": details,
                    "caDebug": ca_debug,
                })
                print(f"DETECT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")

            else:
                result = ensure_policy(
                    headers=headers,
                    display_name=DISPLAY,
                    payload=desired,
                    allow_update=True
                    
                )

                print(f"{result['result'].upper()}: {DISPLAY} | {result['policyId']} | status={result['status']}")

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": f"ensure_{result['result']}",
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "state": ("COMPLIANT" if int(result.get("status") or 0) < 400 else "NOT_EVALUATED"),
                    "reasonCode": ("ENFORCER_EXECUTED" if int(result.get("status") or 0) < 400 else "ENFORCER_ERROR"),
                    "reason": (f"Conditional Access policy ensure result: {result.get('result')}" if int(result.get("status") or 0) < 400 else "Conditional Access policy ensure failed (see errorBody/errorText)"),
                    "mode": mode,
                    "status": result["status"],
                    "policyId": result["policyId"],
                    "payload": result.get("payload"),
                    "errorBody": result.get("errorBody"),
                    "errorText": result.get("errorText"),
                    "caDebug": result.get("caDebug") or ca_debug,
                })
                print(f"Audit saved: {audit_path}")
        elif control_id == "DisableUserConsentToApps":
            import requests

            # Effective mode: approval can override, else control default
            mode_eff = (approval.get("mode") if approval else control.get("default_mode", "report-only"))

            url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"

            # Desired: ONLY the recommended permission grant policy (disables user consent for apps)
            desired = [
                "ManagePermissionGrantsForSelf.microsoft-user-default-recommended"
            ]

            # Read current
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code >= 400:
                return_not_evaluated(
                    write_audit_event=write_audit_event,
                    tenant_name=tenant_name,
                    control_id=control_id,
                    control=control,
                    mode=mode_eff,
                    approval=approval,
                    reason=f"Graph read failed: {r.status_code}",
                    details={"url": url, "errorText": r.text[:500]},
                )
                continue

            body = r.json() or {}
            cur = (((body.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned")) or [])
            cur = [x for x in cur if isinstance(x, str) and x.strip()]

            details = {
                "before": {"permissionGrantPoliciesAssigned": cur},
                "desired": {"permissionGrantPoliciesAssigned": desired},
            }

            # Report-only: evaluate drift, don't change
            if mode_eff == "report-only":
                state = "COMPLIANT" if cur == desired else "DRIFTED"
                reason_code = "REPORT_ONLY_EVALUATED"
                reason_detail = "Report-only: evaluated authorizationPolicy permission grant policies; no changes applied"
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_report_only",
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode_eff,
                    "state": state,
                    "reasonCode": reason_code,
                    "reasonDetail": reason_detail,
                    "details": details,
                    "status": 200,
                })
                print(f"DETECT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            # Enforce: PATCH then re-read
            if mode_eff == "enforce":
                patch = {
                    "defaultUserRolePermissions": {
                        "permissionGrantPoliciesAssigned": desired
                    }
                }
                pr = requests.patch(url, headers={**headers, "Content-Type": "application/json"}, json=patch, timeout=30)

                details["apply"] = {"status": pr.status_code, "response": (pr.text[:500] if pr.text else None)}

                if pr.status_code >= 400:
                    state = "ERROR"
                    reason_code = "ENFORCER_ERROR"
                    reason_detail = f"Graph patch failed: {pr.status_code}"
                else:
                    # verify
                    vr = requests.get(url, headers=headers, timeout=30)
                    vb = vr.json() if vr.status_code < 400 else {}
                    after = (((vb.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned")) or [])
                    after = [x for x in after if isinstance(x, str) and x.strip()]
                    details["after"] = {"permissionGrantPoliciesAssigned": after}

                    state = "COMPLIANT" if after == desired else "DRIFTED"
                    reason_code = "ENFORCER_EXECUTED"
                    reason_detail = "Enforcer executed; post-state verified"

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": f"ensure_{'applied' if mode_eff=='enforce' else 'skipped'}",
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode_eff,
                    "state": state,
                    "reasonCode": reason_code,
                    "reasonDetail": reason_detail,
                    "details": details,
                    "status": (details.get("apply") or {}).get("status") or (200 if state != "ERROR" else 500),
                })
                print(f"ENFORCER: {control_id} | state={state} | {reason_code}")
                print(f"Audit saved: {audit_path}")
                continue
        elif control_id == "Tier3AuthorizationPolicyProbe":
            import requests
            mode_eff = (approval.get("mode") if approval else control.get("default_mode", "detect-only"))
            url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"

            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code >= 400:
                return_not_evaluated(
                    write_audit_event=write_audit_event,
                    tenant_name=tenant_name,
                    control_id=control_id,
                    control=control,
                    mode=mode_eff,
                    approval=approval,
                    reason=f"Graph read failed: {r.status_code}",
                    details={"url": url, "errorText": r.text[:500]},
                )
                continue

            body = r.json() or {}
            details = {
                "authorizationPolicy": {
                    "allowEmailVerifiedUsersToJoinOrganization": body.get("allowEmailVerifiedUsersToJoinOrganization"),
                    "allowInvitesFrom": body.get("allowInvitesFrom"),
                    "allowedToSignUpEmailBasedSubscriptions": body.get("allowedToSignUpEmailBasedSubscriptions"),
                    "defaultUserRolePermissions": body.get("defaultUserRolePermissions"),
                }
            }

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "detect",
                "displayName": control.get("name", control_id),
                "approved": bool(approval),
                "mode": mode_eff,
                "state": "COMPLIANT",
                "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
                "reasonDetail": "Authorization policy probe (read-only)",
                "details": details,
                "status": 200,
            })
            print(f"DETECT-ONLY: {control_id} | state=COMPLIANT")
            print(f"Audit saved: {audit_path}")
            continue
            
        elif control_id == "CAAllUsersBlockLegacyAuth":
            from engine.enforcement.policies.ca_all_users_block_legacy_auth import (
                DISPLAY_NAME as DISPLAY,
                build_payload as build_payload,
            )

            mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))
            blocked, safety_details = safety_block_if_no_break_glass(
                control_id=control_id,
                mode=mode,
                approval=approval,
                tenant=tenant,
            )

            if blocked:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "ensure_safety_blocked",
                    "state": "NOT_EVALUATED",
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 409,
                    "details": safety_details,
                    "reason": "Atlas safety gate: prevent tenant lockout",
                })
                reason = None
                if isinstance(safety_details, dict):
                    reason = safety_details.get("reason") or safety_details.get("blockReason")
                if not reason:
                    reason = "Atlas safety gate: prevent tenant lockout (see audit details)"
                print(f"SAFETY_BLOCK: {control_id} | state=NOT_EVALUATED | reason={reason}")

                print(f"Audit saved: {audit_path}")
                continue

            desired = build_payload(mode=mode, exclude_group_id=get_break_glass_group_id(tenant))

            existing, ca_debug = get_ca_policy_by_display_name(headers, DISPLAY)

            if mode == "report-only":
                if not existing:
                    state = "DRIFTED"
                    details = {"reason": "Policy missing (report-only; not creating)", "displayName": DISPLAY}
                else:
                    def _pick(p: dict) -> dict:
                        conditions = (p.get("conditions") or {})
                        users = (conditions.get("users") or {})
                        apps = (conditions.get("applications") or {})
                        return {
                            "state": p.get("state"),
                            "clientAppTypes": conditions.get("clientAppTypes"),
                            "includeUsers": users.get("includeUsers"),
                            "excludeUsers": users.get("excludeUsers"),
                            "includeApplications": apps.get("includeApplications"),
                            "excludeApplications": apps.get("excludeApplications"),
                            "grantControls": p.get("grantControls"),
                        }

                    if _pick(existing) == _pick(desired):
                        state = "COMPLIANT"
                        details = {"reason": "Matches desired (report-only)", "displayName": DISPLAY}
                    else:
                        state = "DRIFTED"
                        details = {
                            "reason": "Drift detected (report-only; not updating)",
                            "displayName": DISPLAY,
                            "desiredSubset": _pick(desired),
                            "existingSubset": _pick(existing),
                        }

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_report_only",
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": mode,
                    "state": state,
                    "details": details,
                    "caDebug": ca_debug,
                })
                print(f"DETECT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")

            else:
                result = ensure_policy(
                    headers=headers,
                    display_name=DISPLAY,
                    payload=desired,
                    allow_update=True
                )

                print(f"{result['result'].upper()}: {DISPLAY} | {result['policyId']} | status={result['status']}")

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": f"ensure_{result['result']}",
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": mode,
                    "state": "ERROR" if int(result.get("status") or 0) >= 400 else "COMPLIANT",
                    "status": result["status"],
                    "policyId": result["policyId"],
                    "payload": result.get("payload"),
                    "errorBody": result.get("errorBody"),
                    "errorText": result.get("errorText"),
                    "caDebug": result.get("caDebug") or ca_debug,
                })
                print(f"Audit saved: {audit_path}")
        elif control_id == "CAAdminMFAAllApps":
            from engine.enforcement.policies.ca_admin_mfa_all_apps import (
                DISPLAY_NAME as DISPLAY,
                build_payload as build_payload,
            )

            mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))
            blocked, safety_details = safety_block_if_no_break_glass(
                control_id=control_id,
                mode=mode,
                approval=approval,
                tenant=tenant,
            )

            if blocked:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "ensure_safety_blocked",
                    "state": "NOT_EVALUATED",
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 409,
                    "details": safety_details,
                    "reason": "Atlas safety gate: prevent tenant lockout",
                })
                reason = None
                if isinstance(safety_details, dict):
                    reason = safety_details.get("reason") or safety_details.get("blockReason")
                if not reason:
                    reason = "Atlas safety gate: prevent tenant lockout (see audit details)"
                print(f"SAFETY_BLOCK: {control_id} | state=NOT_EVALUATED | reason={reason}")

                print(f"Audit saved: {audit_path}")
                continue

            desired = build_payload(mode=mode, exclude_group_id=get_break_glass_group_id(tenant))

            existing, ca_debug = get_ca_policy_by_display_name(headers, DISPLAY)

            # report-only: do NOT create/update; only detect drift
            if mode in ("report-only", "detect-only"):
                if not existing:
                    state = "DRIFTED"
                    details = {"reason": "Policy missing (report-only; not creating)", "displayName": DISPLAY}
                else:
                    def _pick(p: dict) -> dict:
                        conditions = (p.get("conditions") or {})
                        users = (conditions.get("users") or {})
                        apps = (conditions.get("applications") or {})
                        grant = (p.get("grantControls") or {})

                        return {
                            "state": p.get("state"),
                            "clientAppTypes": conditions.get("clientAppTypes"),
                            "includeUsers": users.get("includeUsers"),
                            "excludeUsers": users.get("excludeUsers"),
                            "includeApplications": apps.get("includeApplications"),
                            "excludeApplications": apps.get("excludeApplications"),
                            "builtInControls": grant.get("builtInControls"),
                        }

                    match = (_pick(existing) == _pick(desired))
                    state = "COMPLIANT" if match else "DRIFTED"
                    details = {"policyId": existing.get("id"), "match": match}

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "report_only_check",
                    "state": state,
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 200,
                    "details": details,
                    "caDebug": ca_debug,
                })
                print(f"REPORT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            # enforce: create/update allowed
            result = ensure_policy(headers=headers, display_name=DISPLAY, payload=desired, allow_update=True)
            state = "ERROR" if int(result.get("status") or 0) >= 400 else "COMPLIANT"

            if result.get("status") and int(result["status"]) >= 400:
                print("GRAPH_ERROR_RESULT:", result)

            print(f"{result['result'].upper()}: {DISPLAY} | {result['policyId']} | status={result['status']}")

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": f"ensure_{result['result']}",
                "displayName": DISPLAY,
                "approved": bool(approval),
                "mode": mode,
                "status": result.get("status"),
                "state": state,
                "policyId": result.get("policyId"),
                "details": {
                    "result": result,
                    "payload": desired,
                    "caDebug": ca_debug,
                }
            })
            print(f"Audit saved: {audit_path}")

        elif control_id == "CAAdminSignInFrequencySessionTimeout":
            from engine.enforcement.policies.admin_signin_freq_session_timeout import (
                DISPLAY_NAME as DISPLAY,
                build_payload as build_payload,
            )

            mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))
            blocked, safety_details = safety_block_if_no_break_glass(
                control_id=control_id,
                mode=mode,
                approval=approval,
                tenant=tenant,
            )

            if blocked:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "ensure_safety_blocked",
                    "state": "NOT_EVALUATED",
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 409,
                    "details": safety_details,
                    "reason": "Atlas safety gate: prevent tenant lockout",
                })
                reason = None
                if isinstance(safety_details, dict):
                    reason = safety_details.get("reason") or safety_details.get("blockReason")
                if not reason:
                    reason = "Atlas safety gate: prevent tenant lockout (see audit details)"
                print(f"SAFETY_BLOCK: {control_id} | state=NOT_EVALUATED | reason={reason}")

                print(f"Audit saved: {audit_path}")
                continue

            desired = build_payload(mode=mode, exclude_group_id=get_break_glass_group_id(tenant))

            existing, ca_debug = get_ca_policy_by_display_name(headers, DISPLAY)

            # report-only: do NOT create/update; only detect drift
            if mode in ("report-only", "detect-only"):
                if not existing:
                    state = "DRIFTED"
                    details = {"reason": "Policy missing (report-only; not creating)", "displayName": DISPLAY}
                else:
                    def _pick(p: dict) -> dict:
                        conditions = (p.get("conditions") or {})
                        users = (conditions.get("users") or {})
                        apps = (conditions.get("applications") or {})

                        session = (p.get("sessionControls") or {})
                        sign_in_freq = (session.get("signInFrequency") or {})
                        persistent = (session.get("persistentBrowser") or {})

                        return {
                            "state": p.get("state"),
                            "includeRoles": users.get("includeRoles"),
                            "excludeUsers": (users.get("excludeUsers") or []),
                            "includeApplications": apps.get("includeApplications"),
                            "clientAppTypes": conditions.get("clientAppTypes"),
                            "signInFrequency": {
                                "isEnabled": sign_in_freq.get("isEnabled"),
                                "type": sign_in_freq.get("type"),
                                "value": sign_in_freq.get("value"),
                            },
                            "persistentBrowser": {
                                "isEnabled": persistent.get("isEnabled"),
                                "mode": persistent.get("mode"),
                            },
                        }
                    match = (_pick(existing) == _pick(desired))
                    state = "COMPLIANT" if match else "DRIFTED"
                    details = {"policyId": existing.get("id"), "match": match}

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "report_only_check",
                    "state": state,
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 200,
                    "details": details,
                })
                print(f"REPORT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            # enforce: create/update allowed
            result = ensure_policy(headers=headers, display_name=DISPLAY, payload=desired, allow_update=True)
            state = "ERROR" if int(result.get("status") or 0) >= 400 else "COMPLIANT"

            # If Graph returns an error, print it so we can see it immediately
            if result.get("status") and int(result["status"]) >= 400:
                print("GRAPH_ERROR_RESULT:", result)

            print(f"{result['result'].upper()}: {DISPLAY} | {result['policyId']} | status={result['status']}")

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": f"ensure_{result['result']}",
                "displayName": DISPLAY,
                "state": state,
                "approved": bool(approval),
                "mode": mode,
                "status": result.get("status"),
                "policyId": result.get("policyId"),
                "details": {
                    "result": result,         # dump the full ensure_policy return (includes error body/text if present)
                    "payload": desired,       # dump what we actually tried to send (critical for 400s)
                    "caDebug": ca_debug,      # what Graph could see when listing policies
                }
            })
            print(f"Audit saved: {audit_path}")


        elif control_id == "CAAdminPhishingResistantMFA":
            from engine.enforcement.policies.admin_phishing_resistant_mfa import (
                DISPLAY_NAME as DISPLAY,
                build_payload as build_payload,
            )

            mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))
            blocked, safety_details = safety_block_if_no_break_glass(
                control_id=control_id,
                mode=mode,
                approval=approval,
                tenant=tenant,
            )

            if blocked:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "ensure_safety_blocked",
                    "state": "NOT_EVALUATED",
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 409,
                    "details": safety_details,
                    "reason": "Atlas safety gate: prevent tenant lockout",
                })
                reason = None
                if isinstance(safety_details, dict):
                    reason = safety_details.get("reason") or safety_details.get("blockReason")
                if not reason:
                    reason = "Atlas safety gate: prevent tenant lockout (see audit details)"
                print(f"SAFETY_BLOCK: {control_id} | state=NOT_EVALUATED | reason={reason}")

                print(f"Audit saved: {audit_path}")
                continue

            # Look up the auth strength policy ID by name (tenant-specific)
            phishing_strength_id = get_auth_strength_policy_id_by_name(headers, "Phishing-resistant MFA")
            if not phishing_strength_id:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_missing_prerequisite",
                    "state": "NOT_EVALUATED",
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 424,
                    "details": {
                        "missingKeys": ["authenticationStrengthPolicyId"],
                        "lookedUpName": "Phishing-resistant MFA",
                        "reason": "Authentication Strength policy not found in tenant; cannot evaluate/enforce safely.",
                    },
                    "reason": "Missing tenant prerequisite: Authentication Strength policy not found",
                })
                print(f"NOT_EVALUATED: {control_id} | missing prerequisite: Authentication Strength 'Phishing-resistant MFA'")
                print(f"Audit saved: {audit_path}")
                continue

            desired = build_payload(mode=mode, authentication_strength_policy_id=phishing_strength_id,exclude_group_id=get_break_glass_group_id(tenant))
            existing, ca_debug = get_ca_policy_by_display_name(headers, DISPLAY)

            # report-only: do NOT create/update; only detect drift
            if mode in ("report-only", "detect-only"):
                if not existing:
                    state = "DRIFTED"
                    details = {"reason": "Policy missing (report-only; not creating)", "displayName": DISPLAY}
                else:
                    def _pick(p: dict) -> dict:
                        conditions = (p.get("conditions") or {})
                        users = (conditions.get("users") or {})
                        apps = (conditions.get("applications") or {})
                        grant = (p.get("grantControls") or {})
                        auth_strength = (grant.get("authenticationStrength") or {})

                        return {
                            "state": p.get("state"),
                            "includeRoles": users.get("includeRoles"),
                            "excludeUsers": (users.get("excludeUsers") or []),
                            "includeApplications": apps.get("includeApplications"),
                            "clientAppTypes": conditions.get("clientAppTypes"),
                            "builtInControls": grant.get("builtInControls"),
                            "authStrengthId": auth_strength.get("id"),
                        }
                    match = (_pick(existing) == _pick(desired))
                    state = "COMPLIANT" if match else "DRIFTED"
                    details = {"policyId": existing.get("id"), "match": match}


                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "report_only_check",
                    "state": state,
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 200,
                    "details": details,
                })
                print(f"REPORT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            # enforce: create/update allowed
            result = ensure_policy(headers=headers, display_name=DISPLAY, payload=desired, allow_update=True)
            state = "ERROR" if int(result.get("status") or 0) >= 400 else "COMPLIANT"

            # If Graph returns an error, print it so we can see it immediately
            if result.get("status") and int(result["status"]) >= 400:
                print("GRAPH_ERROR_RESULT:", result)

            print(f"{result['result'].upper()}: {DISPLAY} | {result['policyId']} | status={result['status']}")

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": f"ensure_{result['result']}",
                "displayName": DISPLAY,
                "approved": bool(approval),
                "mode": mode,
                "status": result.get("status"),
                "state": state,
                "policyId": result.get("policyId"),
                "details": {
                    "result": result,         # dump the full ensure_policy return (includes error body/text if present)
                    "payload": desired,       # dump what we actually tried to send (critical for 400s)
                    "caDebug": ca_debug,      # what Graph could see when listing policies
                }
            })
            print(f"Audit saved: {audit_path}")
            # If Security Defaults is enabled, we treat this control as COMPLIANT for “legacy auth blocked”
            # because Security Defaults enforces baseline protections that include blocking legacy auth in many tenants,
            # and CA cannot be enabled anyway. We still report explicitly that Security Defaults is driving the result.
            if sec_defaults is True:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect",
                    "state": "COMPLIANT",
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 200,
                    "details": {
                        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
                        "securityDefaultsEnabled": True,
                        "note": "Security Defaults enabled; Conditional Access policies cannot be relied upon/managed.",
                    },
                    "reason": "Security Defaults enabled",
                })
                print(f"COMPLIANT: {control_id} | Security Defaults enabled")
                print(f"Audit saved: {audit_path}")
                continue

            # Otherwise, detect posture by checking for a CA legacy auth block policy.
            # Prefer ATLAS-owned control/policy conventions if present.
            legacy_block = find_legacy_auth_blocking_policy(headers)

            if legacy_block.get("found") is True:
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect",
                    "state": "COMPLIANT" if legacy_block.get("enabled") else "DRIFTED",
                    "displayName": DISPLAY,
                    "approved": bool(approval),
                    "mode": mode,
                    "status": 200,
                    "details": {
                        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
                        "securityDefaultsEnabled": False,
                        "policy": legacy_block,
                    },
                    "reason": "Conditional Access legacy auth block policy evaluated",
                })
                print(f"{'COMPLIANT' if legacy_block.get('enabled') else 'DRIFTED'}: {control_id} | CA legacy auth block policy evaluated")
                print(f"Audit saved: {audit_path}")
                continue

            # If we can't find a relevant CA policy, be explicit (do not guess).
            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "detect",
                "state": "NOT_EVALUATED",
                "displayName": DISPLAY,
                "approved": bool(approval),
                "mode": mode,
                "status": 424,
                "details": {
                    "reasonCode": "MISSING_PREREQUISITE",
                    "missingKeys": ["conditionalAccessPolicyBlockingLegacyAuth"],
                    "securityDefaultsEnabled": False,
                },
                "reason": "Could not find a Conditional Access policy that blocks legacy authentication",
            })
            print(f"NOT_EVALUATED: {control_id} | no CA legacy auth block policy found")
            print(f"Audit saved: {audit_path}")
            continue
        
        elif control_id == "SelfServicePasswordReset":
            # Detect-only path: do NOT enforce
            if detect_only:
                from engine.detectors.entra import detect_self_service_password_reset_status

                state, details = detect_self_service_password_reset_status(tenant)

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_only",
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "mode": "detect-only",
                    "status": 200,
                    "details": details,
                    "reason": "standalone detect-only detector (authenticationMethodsPolicy)",
                })
                print(f"DETECT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            # Approved/enforceable path (respects report-only vs enforce)
            from engine.enforcement.entra import apply_self_service_password_reset

            mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))

            state, details = apply_self_service_password_reset(graph, mode=mode)

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": (
                    "ensure_applied"
                    if state == "UPDATED"
                    else "ensure_skipped_no_drift"
                    if state == "COMPLIANT"
                    else "ensure_error"
                    if state == "ERROR"
                    else "ensure_drifted"
                ),
                "state": state,
                "displayName": control.get("name", control_id),
                "approved": bool(approval),
                "mode": mode,
                "status": 200 if state in ("COMPLIANT", "UPDATED", "DRIFTED") else 500,
                "details": details,
                "reason": "Graph enforcement: authenticationMethodsPolicy.isSelfServicePasswordResetEnabled",
            })

            label = "REPORT-ONLY" if mode == "report-only" else "ENFORCE"
            if state == "NOT_EVALUATED":
                label = "SKIPPED_NOT_EVALUATED"
            print(f"{label}: {control_id} | state={state}")
            print(f"Audit saved: {audit_path}")
            continue
        elif control_id == "GlobalAdminCountOptimised":
            if detect_only:
                from engine.detectors.entra import detect_global_admin_count_optimised_status
                state, details = detect_global_admin_count_optimised_status(tenant)

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_only",
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "mode": "detect-only",
                    "status": 200 if state in ("COMPLIANT", "DRIFTED", "NOT_EVALUATED") else 500,
                    "details": details,
                    "reason": "Graph detect: directoryRoles(Global Administrator) member count",
                })

                label = "DETECT-ONLY"
                if state == "NOT_EVALUATED":
                    label = "DETECT-ONLY"
                print(f"{label}: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            # No enforcement for this control currently
            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "no_handler",
                "state": "NOT_EVALUATED",
                "displayName": control.get("name", control_id),
                "mode": mode,
                "status": 200,
                "details": {"reasonCode": "NO_ENFORCER", "reasonDetail": "No enforcer implemented for this control"},
                "reason": "Detect-only supported; enforcement not implemented",
            })
            print(f"NOT_EVALUATED: {control_id} | no enforcer implemented")
            print(f"Audit saved: {audit_path}")
            continue


        elif control_id == "AdminAccountsSeparateCloudOnly":
            if detect_only:
                from engine.detectors.entra import detect_admin_accounts_separate_cloud_only_status
                state, details = detect_admin_accounts_separate_cloud_only_status(tenant)

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_only",
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "mode": "detect-only",
                    "status": 200 if state in ("COMPLIANT", "DRIFTED", "NOT_EVALUATED") else 500,
                    "details": details,
                    "reason": "Graph detect: Global Administrator members onPremisesSyncEnabled (cloud-only check)",
                })

                print(f"DETECT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "no_handler",
                "state": "NOT_EVALUATED",
                "displayName": control.get("name", control_id),
                "mode": mode,
                "status": 200,
                "details": {"reasonCode": "NO_ENFORCER", "reasonDetail": "No enforcer implemented for this control"},
                "reason": "Detect-only supported; enforcement not implemented",
            })
            print(f"NOT_EVALUATED: {control_id} | no enforcer implemented")
            print(f"Audit saved: {audit_path}")
            continue


        elif control_id == "AdminConsentWorkflowEnabled":
            if detect_only:
                from engine.detectors.entra import detect_admin_consent_workflow_enabled_status
                state, details = detect_admin_consent_workflow_enabled_status(tenant)

                from engine.enforcement.graph_singleton import graph_get_json, graph_patch_json, verify_with_retries

                # Effective mode: approval can override, else control default
                mode_eff = (approval.get("mode") if approval else control.get("default_mode", "report-only"))

                url = "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"

                # Read current
                status, body, text = graph_get_json(url, headers=headers, timeout=30)
                if status >= 400:
                    return_not_evaluated(
                        write_audit_event=write_audit_event,
                        tenant_name=tenant_name,
                        control_id=control_id,
                        control=control,
                        mode=mode_eff,
                        approval=approval,
                        reason=f"Graph read failed: {status}",
                        details={"url": url, "errorText": (text or "")[:500]},
                    )
                    continue

                before_enabled = body.get("isEnabled", None)

                details = {
                    "before": {"isEnabled": before_enabled},
                    "desired": {"isEnabled": True},
                    "url": url,
                }

                # Report-only: evaluate drift, don't change
                if mode_eff == "report-only":
                    if before_enabled is True:
                        state = "COMPLIANT"
                    elif before_enabled is False:
                        state = "DRIFTED"
                    else:
                        state = "NOT_EVALUATED"

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_report_only",
                        "displayName": control.get("name", control_id),
                        "approved": bool(approval),
                        "mode": mode_eff,
                        "state": state,
                        "reasonCode": "REPORT_ONLY_EVALUATED",
                        "reasonDetail": "Report-only: evaluated adminConsentRequestPolicy.isEnabled; no changes applied",
                        "details": details,
                        "status": 200,
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                # Enforce: PATCH then verify (with small retry for propagation)
                if mode_eff == "enforce":
                    from engine.enforcement.graph_singleton import graph_put_json

                    # Conservative: only enforce if we have the full policy fields we must preserve
                    required_fields = ["notifyReviewers", "remindersEnabled", "requestDurationInDays", "reviewers"]
                    missing = [k for k in required_fields if k not in body]

                    if missing:
                        audit_path = _write_audit_event_timed(tenant_name, {
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "ensure_applied",
                            "displayName": control.get("name", control_id),
                            "approved": bool(approval),
                            "mode": mode_eff,
                            "state": "NOT_EVALUATED",
                            "reasonCode": "INSUFFICIENT_SIGNAL",
                            "reasonDetail": f"Refusing to enforce: missing required fields from GET: {missing}",
                            "details": {**details, "missingRequiredFields": missing},
                            "status": 200,
                        })
                        print(f"NOT_EVALUATED: {control_id} | insufficient signal (missing {missing})")
                        print(f"Audit saved: {audit_path}")
                        continue

                    put_payload = {
                        "isEnabled": True,
                        "notifyReviewers": body["notifyReviewers"],
                        "remindersEnabled": body["remindersEnabled"],
                        "requestDurationInDays": body["requestDurationInDays"],
                        "reviewers": body["reviewers"],
                    }

                    p_status, p_body, p_text = graph_put_json(url, headers=headers, payload=put_payload, timeout=30)


                    details["apply"] = {
                        "status": p_status,
                        "response": (p_text or "")[:500] if p_text else None,
                    }

                    if p_status >= 400:
                        state = "ERROR"
                        reason_code = "ENFORCER_ERROR"
                        reason_detail = f"Graph put failed: {p_status}"
                    else:
                        def _get():
                            return graph_get_json(url, headers=headers, timeout=30)

                        def _is_desired(b: dict) -> bool:
                            return b.get("isEnabled", None) is True

                        v_status, v_body, v_text, attempt_used = verify_with_retries(
                            get_fn=_get,
                            is_desired_fn=_is_desired,
                            attempts=5,
                            delay_seconds=2.0,
                        )

                        after_enabled = (v_body or {}).get("isEnabled", None)
                        details["after"] = {"isEnabled": after_enabled}
                        details["verify"] = {"status": v_status, "attempt": attempt_used, "response": (v_text or "")[:500]}

                        if after_enabled is True:
                            state = "COMPLIANT"
                        elif after_enabled is False:
                            state = "DRIFTED"
                        else:
                            state = "NOT_EVALUATED"

                        reason_code = "ENFORCER_EXECUTED"
                        reason_detail = "Enforcer executed; post-state verified"

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "ensure_applied",
                        "displayName": control.get("name", control_id),
                        "approved": bool(approval),
                        "mode": mode_eff,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                        "status": (details.get("apply") or {}).get("status") or (200 if state != "ERROR" else 500),
                    })
                    print(f"ENFORCER: {control_id} | state={state} | {reason_code}")
                    print(f"Audit saved: {audit_path}")
                    continue

                # If mode is something unexpected, fall back safely
                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "no_handler",
                    "state": "NOT_EVALUATED",
                    "displayName": control.get("name", control_id),
                    "approved": bool(approval),
                    "mode": mode_eff,
                    "status": 200,
                    "details": {
                        "reasonCode": "NO_ENFORCER",
                        "reasonDetail": f"Unsupported mode for enforcer: {mode_eff}",
                        **details,
                    },
                    "reason": "Unsupported mode",
                })
                print(f"NOT_EVALUATED: {control_id} | unsupported mode={mode_eff}")
                print(f"Audit saved: {audit_path}")
                continue



        elif control_id == "LimitedAdminRolesAzureManagement":
            if detect_only:
                from engine.detectors.entra import detect_limited_admin_roles_azure_management_status
                state, details = detect_limited_admin_roles_azure_management_status(tenant)

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_only",
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "mode": "detect-only",
                    "status": 200 if state in ("COMPLIANT", "DRIFTED", "NOT_EVALUATED") else 500,
                    "details": details,
                    "reason": "Graph detect: servicePrincipal(Microsoft Azure Management).appRoleAssignmentRequired",
                })

                print(f"DETECT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "no_handler",
                "state": "NOT_EVALUATED",
                "displayName": control.get("name", control_id),
                "mode": mode,
                "status": 200,
                "details": {"reasonCode": "NO_ENFORCER", "reasonDetail": "No enforcer implemented for this control"},
                "reason": "Detect-only supported; enforcement not implemented",
            })
            print(f"NOT_EVALUATED: {control_id} | no enforcer implemented")
            print(f"Audit saved: {audit_path}")
            continue


        elif control_id == "RoleOverlap":
            if detect_only:
                from engine.detectors.entra import detect_role_overlap_status
                state, details = detect_role_overlap_status(tenant)

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_only",
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "mode": "detect-only",
                    "status": 200 if state in ("COMPLIANT", "DRIFTED", "NOT_EVALUATED") else 500,
                    "details": details,
                    "reason": "Graph detect: privileged directory role overlap (selected roles)",
                })

                print(f"DETECT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "no_handler",
                "state": "NOT_EVALUATED",
                "displayName": control.get("name", control_id),
                "mode": mode,
                "status": 200,
                "details": {"reasonCode": "NO_ENFORCER", "reasonDetail": "No enforcer implemented for this control"},
                "reason": "Detect-only supported; enforcement not implemented",
            })
            print(f"NOT_EVALUATED: {control_id} | no enforcer implemented")
            print(f"Audit saved: {audit_path}")
            continue


        elif control_id in ("IntegratedAppsRestricted", "ThirdPartyAppsRestricted"):
            # Reuse existing consent detector (conservative: proves consent restriction only)
            if detect_only:
                from engine.detectors.entra import detect_disable_user_consent_to_apps_status
                state, details = detect_disable_user_consent_to_apps_status(tenant)

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_only",
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "mode": "detect-only",
                    "status": 200 if state in ("COMPLIANT", "DRIFTED", "NOT_EVALUATED") else 500,
                    "details": details,
                    "reason": "Graph detect: policies/authorizationPolicy permissionGrantPoliciesAssigned (user consent restriction)",
                })

                print(f"DETECT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": "no_handler",
                "state": "NOT_EVALUATED",
                "displayName": control.get("name", control_id),
                "mode": mode,
                "status": 200,
                "details": {"reasonCode": "NO_ENFORCER", "reasonDetail": "No enforcer implemented for this control"},
                "reason": "Detect-only supported; enforcement not implemented",
            })
            print(f"NOT_EVALUATED: {control_id} | no enforcer implemented")
            print(f"Audit saved: {audit_path}")
            continue

        elif control_id == "MDOPresetSecurityPolicies":
            # Detect-only path
            if detect_only:
                from engine.detectors.mdo import detect_preset_security_policies_status

                state, details = detect_preset_security_policies_status(tenant)

                audit_path = _write_audit_event_timed(tenant_name, {
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "detect_only",
                    "state": state,
                    "displayName": control.get("name", control_id),
                    "mode": "detect-only",
                    "status": 200,
                    "details": details,
                    "reason": "standalone detect-only detector",
                })
                print(f"DETECT-ONLY: {control_id} | state={state}")
                print(f"Audit saved: {audit_path}")
                continue

            # Enforcement / approved path
            from engine.enforcement.mdo_preset import apply_mdo_preset_security_policies

            mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))
            level = (tenant.get("mdoPresetPolicyLevel") or "standard")

            state, details = apply_mdo_preset_security_policies(
                tenant=tenant,
                mode=mode,
                level=level,
            )

            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": (
                    "ensure_applied"
                    if state == "UPDATED"
                    else "ensure_skipped_no_drift"
                    if state == "COMPLIANT"
                    else "ensure_not_evaluated"
                    if state == "NOT_EVALUATED"
                    else "ensure_error"
                ),
                "state": state,
                "displayName": control.get("name", control_id),
                "approved": bool(approval),
                "mode": mode,
                "status": 200 if state in ("COMPLIANT", "UPDATED", "DRIFTED") else 500,
                "details": details,
                "reason": "EXO PowerShell enforcement: preset security policies",
            })

            label = "REPORT-ONLY" if mode == "report-only" else "ENFORCE"
            if state == "NOT_EVALUATED":
                label = "SKIPPED_NOT_EVALUATED"
            print(f"{label}: {control_id} | state={state}")

            print(f"Audit saved: {audit_path}")
            continue


            # Otherwise, enforce
            from engine.enforcement.entra import apply_self_service_password_reset

            mode = (approval.get("mode") if approval else control.get("default_mode", "report-only"))
            state, details = apply_self_service_password_reset(graph, mode=mode)


            audit_path = _write_audit_event_timed(tenant_name, {
                "tenant": tenant_name,
                "controlId": control_id,
                "action": (
                    "ensure_applied"
                    if state == "UPDATED"
                    else "ensure_skipped_no_drift"
                    if state == "COMPLIANT"
                    else "ensure_error"
                ),
                "state": state,
                "displayName": control.get("name", control_id),
                "mode": mode,
                "status": 200 if state in ("COMPLIANT", "UPDATED") else 500,
                "details": details,
                "reason": "Graph enforcement: authenticationMethodsPolicy.isSelfServicePasswordResetEnabled",
            })

            label = "REPORT-ONLY" if mode == "report-only" else "ENFORCE"
            if state == "NOT_EVALUATED":
                label = "SKIPPED_NOT_EVALUATED"
            print(f"{label}: {control_id} | state={state}")

            print(f"Audit saved: {audit_path}")
            continue
        else:
            # Generic detect-only control behavior (no enforcement)
            if str(mode).strip().lower() == "detect-only" or control.get("detectOnly") is True:

                # Use Secure Score scorePct as the detector signal:
                # <100 means not fully implemented => DRIFTED
                scorepct = f.get("scorePct", None)
                reason_code = None
                reason_detail = None

                # If this control is driven by Secure Score IDs, derive score from those IDs
                linked = control.get("secureScoreControlIds") or []
                if linked:
                    scores = []
                    missing_ids = []

                    for ssid in linked:
                        # Normalize Secure Score IDs for consistent lookups everywhere
                        key = (ssid or "").strip().lower()
                        if not key:
                            continue

                        # If the Secure Score control ID doesn't exist in this tenant's profiles,
                        # it's not something we can fairly score (often licensing / not applicable).
                        if key not in known_secure_score_ids:
                            missing_ids.append(key)
                            continue

                        ff = findings_by_ssid.get(key)
                        if ff and ff.get("scorePct") is not None:
                            try:
                                scores.append(float(ff["scorePct"]))
                            except Exception:
                                pass
                        else:
                            # No finding returned for this Secure Score controlId in this tenant.
                            # This is missing signal, not drift.
                            missing_ids.append(key)
                            continue



                    # If *all* linked IDs are missing, we cannot evaluate this control in this tenant
                    if not scores and missing_ids:
                        scorepct = None
                        # We'll later emit NOT_EVALUATED instead of DRIFTED for these.
                        f = f or {}
                        f["missingSecureScoreControlIds"] = missing_ids
                    elif scores:
                        scorepct = min(scores)
                    

                if control_id == "MDETamperProtectionStatus":
                    from engine.detectors.mde import detect_tamper_protection_status
                    state, details = detect_tamper_protection_status()

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "standalone detect-only detector",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue    
                if control_id == "EXOMailTipsEnabled":
                    from engine.detectors.mdo import detect_exo_mailtips_enabled_status

                    res = detect_exo_mailtips_enabled_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "DETECTOR_ERROR")
                    reason_detail = res.get("reasonDetail")

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ["COMPLIANT", "DRIFTED"] else 424,
                            "details": details,
                        }, reason_code, reason_detail),
                    )

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "CustomerLockboxEnabled":
                    from engine.detectors.mdo import detect_customer_lockbox_enabled_status

                    res = detect_customer_lockbox_enabled_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "DETECTOR_ERROR")
                    reason_detail = res.get("reasonDetail")

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200,
                            "details": details,
                        }, reason_code, reason_detail),
                    )
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "PurviewAutoLabelingPolicies":
                    from engine.detectors.mdo import detect_purview_auto_labeling_policies_status

                    res = detect_purview_auto_labeling_policies_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "DETECTOR_ERROR")
                    reason_detail = res.get("reasonDetail")

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ["COMPLIANT", "DRIFTED"] else 424,
                            "details": details,
                        }, reason_code, reason_detail),
                    )
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "PurviewLabelConsentDataMap":
                    from engine.detectors.mdo import detect_purview_label_consent_datamap_status

                    res = detect_purview_label_consent_datamap_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "DETECTOR_ERROR")
                    reason_detail = res.get("reasonDetail")

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ["COMPLIANT", "DRIFTED"] else 424,
                            "details": details,
                        }, reason_code, reason_detail),
                    )
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "DefenderForIdentityDeployed":
                    from engine.detectors.mdi import detect_defender_for_identity_deployed

                    res = detect_defender_for_identity_deployed(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "DETECTOR_ERROR")
                    reason_detail = res.get("reasonDetail")

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ["COMPLIANT", "DRIFTED"] else 424,
                            "details": details,
                        }, reason_code, reason_detail),
                    )
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "McasFirewallLogUpload":
                    from engine.detectors.mcas import detect_mcas_firewall_log_upload_configured

                    res = detect_mcas_firewall_log_upload_configured(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "DETECTOR_ERROR")
                    reason_detail = res.get("reasonDetail")

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ["COMPLIANT", "DRIFTED"] else 424,
                            "details": details,
                        }, reason_code, reason_detail),
                    )

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "EXOStorageProvidersRestricted":
                    from engine.detectors.mdo import detect_exo_storage_providers_restricted_status

                    res = detect_exo_storage_providers_restricted_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "DETECTOR_ERROR")
                    reason_detail = res.get("reasonDetail")

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ["COMPLIANT", "DRIFTED"] else 424,
                            "details": details,
                        }, reason_code, reason_detail),
                    )

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "MDOSafeLinks":
                    from engine.detectors.mdo import detect_safe_links_status
                    state, details = detect_safe_links_status(tenant)

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "standalone detect-only detector",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "MDOSafeAttachments":
                    from engine.detectors.mdo import detect_safe_attachments_status
                    state, details = detect_safe_attachments_status(tenant)

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "standalone detect-only detector",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "AuditLogSearchEnabled":
                    from engine.detectors.mdo import detect_audit_log_search_enabled_status

                    res = detect_audit_log_search_enabled_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "DETECTOR_ERROR")
                    reason_detail = res.get("reasonDetail")

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ("COMPLIANT", "DRIFTED") else 424,
                            "details": details,
                        }, reason_code, reason_detail)
                    )

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "EXOCalendarExternalSharingDisabled":
                    from engine.detectors.mdo import detect_exo_calendar_external_sharing_disabled_status

                    res = detect_exo_calendar_external_sharing_disabled_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "EXOOutlookAddinsBlocked":
                    from engine.detectors.mdo import detect_exo_outlook_addins_blocked_status

                    res = detect_exo_outlook_addins_blocked_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "EXOSPFRecordsAllDomains":
                    from engine.detectors.mdo import detect_exo_spf_records_all_domains_status

                    res = detect_exo_spf_records_all_domains_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOAllowedSendersRestricted":
                    from engine.detectors.mdo import detect_mdo_allowed_senders_restricted_status

                    res = detect_mdo_allowed_senders_restricted_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOBulkComplaintLevelThreshold":
                    from engine.detectors.mdo import detect_mdo_bulk_complaint_level_threshold_status

                    res = detect_mdo_bulk_complaint_level_threshold_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOBulkSpamAction":
                    from engine.detectors.mdo import detect_mdo_bulk_spam_action_status

                    res = detect_mdo_bulk_spam_action_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOHighConfidenceSpamAction":
                    from engine.detectors.mdo import detect_mdo_high_confidence_spam_action_status

                    res = detect_mdo_high_confidence_spam_action_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOPhishingAction":
                    from engine.detectors.mdo import detect_mdo_phishing_action_status

                    res = detect_mdo_phishing_action_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOThresholdReachedAction":
                    from engine.detectors.mdo import detect_mdo_threshold_reached_action_status

                    res = detect_mdo_threshold_reached_action_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOQuarantineRetentionPeriod":
                    from engine.detectors.mdo import detect_mdo_quarantine_retention_period_status

                    res = detect_mdo_quarantine_retention_period_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOSafeDocumentsEnabled":
                    from engine.detectors.mdo import detect_mdo_safe_documents_enabled_status

                    res = detect_mdo_safe_documents_enabled_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOSafeLinksOfficeApps":
                    from engine.detectors.mdo import detect_mdo_safe_links_office_apps_status

                    res = detect_mdo_safe_links_office_apps_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOSafetyTipsEnabled":
                    from engine.detectors.mdo import detect_mdo_safety_tips_enabled_status

                    res = detect_mdo_safety_tips_enabled_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOSpamNotificationsAdminsOnly":
                    from engine.detectors.mdo import detect_mdo_spam_notifications_admins_only_status

                    res = detect_mdo_spam_notifications_admins_only_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOAntiPhishingPoliciesTuned":
                    from engine.detectors.mdo import detect_mdo_anti_phishing_policies_tuned_status

                    res = detect_mdo_anti_phishing_policies_tuned_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOBlockAutoForwarding":
                    from engine.detectors.mdo import detect_mdo_block_auto_forwarding_status

                    res = detect_mdo_block_auto_forwarding_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOMailboxIntelligenceActionsConfigured":
                    from engine.detectors.mdo import detect_mdo_mailbox_intelligence_actions_configured_status

                    res = detect_mdo_mailbox_intelligence_actions_configured_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOMailboxIntelligenceProtection":
                    from engine.detectors.mdo import detect_mdo_mailbox_intelligence_protection_status

                    res = detect_mdo_mailbox_intelligence_protection_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOPhishThresholdLevel":
                    from engine.detectors.mdo import detect_mdo_phish_threshold_level_status

                    res = detect_mdo_phish_threshold_level_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOTargetedUsersProtection":
                    from engine.detectors.mdo import detect_mdo_targeted_users_protection_status

                    res = detect_mdo_targeted_users_protection_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOTargetedDomainProtection":
                    from engine.detectors.mdo import detect_mdo_targeted_domain_protection_status

                    res = detect_mdo_targeted_domain_protection_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOTargetedDomainProtectionAction":
                    from engine.detectors.mdo import detect_mdo_targeted_domain_protection_action_status

                    res = detect_mdo_targeted_domain_protection_action_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOTargetedUserProtectionAction":
                    from engine.detectors.mdo import detect_mdo_targeted_user_protection_action_status

                    res = detect_mdo_targeted_user_protection_action_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "MDOTurnOnMDOForSPOODTeams":
                    from engine.detectors.mdo import detect_mdo_turn_on_mdo_for_spood_teams_status

                    res = detect_mdo_turn_on_mdo_for_spood_teams_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "CUSTOM_DETECTOR_EVALUATED")
                    reason_detail = res.get("reasonDetail", "Custom detector evaluated")
                    audit = {
                        "controlId": control_id,
                        "name": control.get("name", control_id),
                        "category": control.get("category"),
                        "tier": control.get("tier"),
                        "mode": mode,
                        "state": state,
                        "reasonCode": reason_code,
                        "reasonDetail": reason_detail,
                        "details": details,
                    }
                    audit_path = _write_audit_event_timed(tenant_name, audit, _started_at)
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "MailboxAuditingEnabled":
                    from engine.detectors.mdo import detect_mailbox_auditing_enabled_status

                    res = detect_mailbox_auditing_enabled_status(tenant)
                    state = res.get("state", "NOT_EVALUATED")
                    details = res.get("details", {})
                    reason_code = res.get("reasonCode", "DETECTOR_ERROR")
                    reason_detail = res.get("reasonDetail")

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ["COMPLIANT", "DRIFTED"] else 424,
                            "details": details,
                        }, reason_code, reason_detail),
                    )

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "MDOAntiPhish":
                    from engine.detectors.mdo import detect_anti_phish_status
                    state, details = detect_anti_phish_status(tenant)

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "standalone detect-only detector",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "MDOAntiSpam":
                    from engine.detectors.mdo import detect_anti_spam_status
                    state, details = detect_anti_spam_status(tenant)

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "standalone detect-only detector",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "MDOAntiMalware":
                    from engine.detectors.mdo import detect_anti_malware_status
                    state, details = detect_anti_malware_status(tenant)

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "standalone detect-only detector",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "MDOPresetSecurityPolicies":
                    from engine.detectors.mdo import detect_preset_security_policies_status
                    state, details = detect_preset_security_policies_status(tenant)

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "standalone detect-only detector",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "SharePointIdleSessionTimeout":
                    admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                    admin_url = (admin_url or "").strip()

                    if not admin_url:
                        state = "NOT_EVALUATED"
                        reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                        reason_detail = "spoAdminUrl not set; cannot run SPO fallback detector for idle session timeout"
                        details = {"missingKeys": ["spoAdminUrl"]}
                        fallback = None
                    else:
                        spo = get_spo_tenant_settings_cached(admin_url)

                        fallback = {"name": "spo_tenant_settings", "result": spo}

                        if not spo.get("ok"):
                            state = "NOT_EVALUATED"
                            reason_code = "FALLBACK_DETECTOR_ERROR"
                            reason_detail = f"SPO fallback detector failed: {spo.get('error')}"
                            details = {
                                "error": spo.get("error"),
                                "raw": spo.get("raw"),
                                "stderr": spo.get("stderr"),
                            }
                        else:
                            t = (spo.get("tenant") or {})

                            enabled = t.get("IdleSessionSignOutEnabled")
                            warn_s = t.get("IdleSessionSignOutWarnAfterSeconds")
                            signout_s = t.get("IdleSessionSignOutAfterSeconds")

                            details = {
                                "IdleSessionSignOutEnabled": enabled,
                                "IdleSessionSignOutWarnAfterSeconds": warn_s,
                                "IdleSessionSignOutAfterSeconds": signout_s,
                            }

                            missing = []
                            if enabled is None:
                                missing.append("IdleSessionSignOutEnabled")
                            if warn_s is None:
                                missing.append("IdleSessionSignOutWarnAfterSeconds")
                            if signout_s is None:
                                missing.append("IdleSessionSignOutAfterSeconds")

                            if missing:
                                state = "NOT_EVALUATED"
                                reason_code = "MISSING_DATA"
                                reason_detail = "SPO tenant settings did not return required idle session timeout fields"
                                details["missingKeys"] = missing
                            else:
                                enabled_norm = enabled if isinstance(enabled, bool) else str(enabled).strip().lower() in ("true", "1", "yes")
                                ok_nums = isinstance(warn_s, int) and isinstance(signout_s, int) and warn_s > 0 and signout_s > warn_s

                                details["IdleSessionSignOutEnabled_normalized"] = enabled_norm
                                details["IdleSessionSignOutNumbersValid"] = ok_nums

                                state = "COMPLIANT" if (enabled_norm and ok_nums) else "DRIFTED"
                                reason_code = "FALLBACK_DETECTOR_EVALUATED"
                                reason_detail = "Evaluated via SharePoint tenant settings (SPO PowerShell)"

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ("COMPLIANT", "DRIFTED") else 424,
                            "details": details,
                            "fallbackDetector": fallback,
                        }, reason_code, reason_detail)
                    )

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "SharePointExternalSharingManaged":
                    admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                    admin_url = (admin_url or "").strip()

                    if not admin_url:
                        state = "NOT_EVALUATED"
                        reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                        reason_detail = "spoAdminUrl not set; cannot run SPO fallback detector for external sharing management"
                        details = {"missingKeys": ["spoAdminUrl"]}
                        fallback = None
                    else:
                        spo = get_spo_tenant_settings_cached(admin_url)
                        fallback = {"name": "spo_tenant_settings", "result": spo}

                        if not spo.get("ok"):
                            state = "NOT_EVALUATED"
                            reason_code = "FALLBACK_DETECTOR_ERROR"
                            reason_detail = f"SPO fallback detector failed: {spo.get('error')}"
                            details = {
                                "error": spo.get("error"),
                                "raw": spo.get("raw"),
                                "stderr": spo.get("stderr"),
                            }
                        else:
                            t = (spo.get("tenant") or {})
                            mode = t.get("SharingDomainRestrictionMode")
                            allow_list = t.get("SharingAllowedDomainList")
                            block_list = t.get("SharingBlockedDomainList")

                            details = {
                                "SharingDomainRestrictionMode": mode,
                                "SharingAllowedDomainList": allow_list,
                                "SharingBlockedDomainList": block_list,
                            }

                            if mode is None:
                                state = "NOT_EVALUATED"
                                reason_code = "MISSING_DATA"
                                reason_detail = "SPO tenant settings did not return SharingDomainRestrictionMode"
                                details["missingKeys"] = ["SharingDomainRestrictionMode"]
                            else:
                                # Conservative: managed == non-zero mode (allow-list or block-list mode)
                                state = "COMPLIANT" if int(mode) != 0 else "DRIFTED"
                                reason_code = "FALLBACK_DETECTOR_EVALUATED"
                                reason_detail = "Evaluated via SharePoint tenant settings (SPO PowerShell)"

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ("COMPLIANT", "DRIFTED") else 424,
                            "details": details,
                            "fallbackDetector": fallback,
                        }, reason_code, reason_detail)
                    )

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                if control_id == "SharePointModernAuthRequired":
                    admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                    admin_url = (admin_url or "").strip()

                    if not admin_url:
                        state = "NOT_EVALUATED"
                        reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                        reason_detail = "spoAdminUrl not set; cannot run SPO fallback detector for modern auth requirement"
                        details = {"missingKeys": ["spoAdminUrl"]}
                        fallback = None
                    else:
                        spo = get_spo_tenant_settings_cached(admin_url)
                        fallback = {"name": "spo_tenant_settings", "result": spo}

                        if not spo.get("ok"):
                            state = "NOT_EVALUATED"
                            reason_code = "FALLBACK_DETECTOR_ERROR"
                            reason_detail = f"SPO fallback detector failed: {spo.get('error')}"
                            details = {
                                "error": spo.get("error"),
                                "raw": spo.get("raw"),
                                "stderr": spo.get("stderr"),
                            }
                        else:
                            t = (spo.get("tenant") or {})
                            legacy = t.get("LegacyAuthProtocolsEnabled")
                            details = {"LegacyAuthProtocolsEnabled": legacy}

                            if legacy is None:
                                state = "NOT_EVALUATED"
                                reason_code = "MISSING_DATA"
                                reason_detail = "SPO tenant settings did not return LegacyAuthProtocolsEnabled"
                                details["missingKeys"] = ["LegacyAuthProtocolsEnabled"]
                            else:
                                legacy_norm = legacy if isinstance(legacy, bool) else str(legacy).strip().lower() in ("true", "1", "yes")
                                details["LegacyAuthProtocolsEnabled_normalized"] = legacy_norm

                                # Compliant when legacy auth protocols are disabled
                                state = "COMPLIANT" if (legacy_norm is False) else "DRIFTED"
                                reason_code = "FALLBACK_DETECTOR_EVALUATED"
                                reason_detail = "Evaluated via SharePoint tenant settings (SPO PowerShell)"

                    audit_path = _write_audit_event_timed(
                        tenant_name,
                        attach_reason({
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "detect_only",
                            "state": state,
                            "displayName": control.get("name", control_id),
                            "mode": "detect-only",
                            "status": 200 if state in ("COMPLIANT", "DRIFTED") else 424,
                            "details": details,
                            "fallbackDetector": fallback,
                        }, reason_code, reason_detail)
                    )

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "EXODKIMEnabledAllDomains":
                    from engine.detectors.dns_email import detect_dkim_enabled_all_domains

                    state, details = detect_dkim_enabled_all_domains(tenant)


                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "DNS-based DKIM detector",
                    })

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "EXODMARCAllDomains":
                    from engine.detectors.dns_email import detect_dmarc_all_domains

                    state, details = detect_dmarc_all_domains(tenant)


                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "DNS-based DMARC detector",
                    })

                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "DisableUserConsentToApps":
                    from engine.detectors.entra import detect_disable_user_consent_to_apps_status

                    # --- ENFORCE path ---
                    if mode == "enforce":
                        try:
                            import requests
                            from engine.auth.token import get_access_token

                            token = get_access_token(tenant)
                            url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"

                            body = {
                                "defaultUserRolePermissions": {
                                    "permissionGrantPoliciesAssigned": [
                                        "ManagePermissionGrantsForSelf.microsoft-user-default-recommended"
                                    ]

                                }
                            }

                            r = requests.patch(
                                url,
                                headers={
                                    "Authorization": f"Bearer {token}",
                                    "Content-Type": "application/json",
                                },
                                json=body,
                                timeout=30,
                            )

                            if r.status_code in (200, 204):
                                detector_result = {
                                    "state": "COMPLIANT",
                                    "details": {
                                        "endpoint": url,
                                        "changed": True,
                                        "httpStatus": r.status_code,
                                        "applied": body,
                                    },
                                    "reasonCode": "ENFORCER_EXECUTED",
                                    "reasonDetail": "User consent to apps disabled by clearing permissionGrantPoliciesAssigned.",
                                }
                            else:
                                detector_result = {
                                    "state": "NOT_EVALUATED",
                                    "details": {
                                        "endpoint": url,
                                        "changed": False,
                                        "httpStatus": r.status_code,
                                        "responseText": (r.text or "")[:4000],
                                        "attempted": body,
                                    },
                                    "reasonCode": "ENFORCER_ERROR",
                                    "reasonDetail": f"Graph PATCH authorizationPolicy failed (HTTP {r.status_code}).",
                                }

                        except Exception as e:
                            detector_result = {
                                "state": "NOT_EVALUATED",
                                "details": {"error": str(e)},
                                "reasonCode": "ENFORCER_ERROR",
                                "reasonDetail": "Exception while enforcing DisableUserConsentToApps.",
                            }

                        audit_path = _write_audit_event_timed(tenant_name, {
                            "tenant": tenant_name,
                            "controlId": control_id,
                            "action": "ensure_user_consent_disabled",
                            "state": detector_result["state"],
                            "displayName": control.get("name", control_id),
                            "mode": "enforce",
                            "status": (detector_result.get("details") or {}).get("httpStatus") or 424,
                            "details": detector_result.get("details") or {},
                            "reason": "Graph enforcement (authorizationPolicy)",
                        })
                        print(f"ENFORCE: {control_id} | state={detector_result['state']}")
                        print(f"Audit saved: {audit_path}")
                        continue

                    # --- DETECT / REPORT-ONLY path ---
                    state, details = detect_disable_user_consent_to_apps_status(tenant)

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": mode,  # keep actual mode (detect-only or report-only)
                        "status": 200,
                        "details": details,
                        "reason": "standalone detect-only detector (Entra authorizationPolicy)",
                    })
                    print(f"{mode.upper()}: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "SelfServicePasswordReset":
                    from engine.detectors.entra import detect_self_service_password_reset_status

                    state, details = detect_self_service_password_reset_status(tenant)

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "standalone detect-only detector (authenticationMethodsPolicy)",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "Tier3AuthMethodsReadiness":
                    from engine.detectors.entra import detect_tier3_auth_methods_readiness

                    state, details = detect_tier3_auth_methods_readiness(tenant)

                    # If this is a Tier 3 summary entry, reflect readiness outcome in the summary
                    if tier3_entry is not None:
                        tier3_entry["outcome"] = state

                        if state == "ERROR":
                            tier3_entry["reason"] = details.get("reason")
                        else:
                            tier3_entry["reason"] = "READY" if details.get("phishingResistantReady") else "NOT_READY"
                            # Add quick method state summary for onboarding readability
                            ms = details.get("methodStates") or {}
                            tier3_entry["methodsSummary"] = f'FIDO2={ms.get("fido2")}, WHfB={ms.get("windowsHelloForBusiness")}, TAP={ms.get("temporaryAccessPass")}'

                        tier3_entry["missing"] = []

                    
                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "Tier 3 readiness detector (Authentication Methods Policy)",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "Tier3BreakGlassReadiness":
                    from engine.detectors.entra import detect_tier3_break_glass_readiness

                    state, details = detect_tier3_break_glass_readiness(tenant)

                    if tier3_entry is not None:
                        tier3_entry["outcome"] = state

                        if state == "ERROR":
                            tier3_entry["reason"] = details.get("reason")
                        else:
                            tier3_entry["reason"] = "READY" if state == "COMPLIANT" else "NOT_READY"
                            # Add quick summary info for onboarding readability
                            tier3_entry["breakGlassSummary"] = f'totalMembers={details.get("totalMembers")}, enabledMembers={len(details.get("enabledMembers") or [])}'
                            if details.get("reason"):
                                tier3_entry["breakGlassReason"] = details.get("reason")

                        tier3_entry["missing"] = []

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": "Tier 3 break-glass readiness detector",
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "Tier3AuthMethodsCatalog":
                    from engine.detectors.auth_methods_catalog import detect_auth_methods_catalog
                    state, details = normalize_detector_result(detect_auth_methods_catalog(headers))
                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "approved": bool(approval),
                        "mode": "detect-only",
                        "status": 200 if state in ("COMPLIANT", "DRIFTED") else 500,
                        "details": details,
                        "reasonCode": details.get("reasonCode"),
                        "reasonDetail": details.get("reasonDetail"),
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id == "Tier3AuthMethodsProbe":
                    from engine.detectors.auth_methods_probe import detect_auth_methods_probe

                    state, details = normalize_detector_result(detect_auth_methods_probe(headers))

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "approved": bool(approval),
                        "mode": "detect-only",
                        "status": 200 if state in ("COMPLIANT", "DRIFTED") else 500,
                        "details": details,
                        "reasonCode": details.get("reasonCode"),
                        "reasonDetail": details.get("reasonDetail"),
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue

                if control_id == "Tier3PerUserMfaReadiness":
                    from engine.detectors.per_user_mfa import detect_per_user_mfa_readiness

                    state, details = normalize_detector_result(detect_per_user_mfa_readiness(headers))

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "approved": bool(approval),
                        "mode": "detect-only",
                        "status": 200 if state in ("COMPLIANT", "DRIFTED") else 500,
                        "details": details,
                        "reasonCode": details.get("reasonCode"),
                        "reasonDetail": details.get("reasonDetail"),
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue


                try:
                    pct = float(scorepct)
                except Exception:
                    pct = None
                # Reset per-control outputs (prevents state/details/reason leaking from the previous control)
                details = {}
                reason_code = None
                reason_detail = None


                # Determine state from pct
                if pct is None and (f or {}).get("missingSecureScoreControlIds"):
                    state = "NOT_EVALUATED"
                else:
                    state = "COMPLIANT" if (pct is not None and pct >= 100) else "DRIFTED"

                missing_ss = (f or {}).get("missingSecureScoreControlIds")

                reason_code = "SECURE_SCORE_ID_MISSING" if missing_ss else "DETECT_ONLY_EVALUATED"
                reason_detail = (
                    "Secure Score controlId referenced by ATLAS but missing from this tenant's controlProfiles"
                    if reason_code == "SECURE_SCORE_ID_MISSING"
                    else "detect-only registry control evaluated via Secure Score"
                )
                # ============================
                # Batch A: SharePoint / OneDrive / Sway
                # Force detect-only controls to use custom detectors (Secure Score stays overlay-only)
                # ============================
                if control_id in {
                    "OneDriveBlockSyncUnmanagedDevices",
                    "SharePointGuestUsersCannotReshare",
                    "SwayBlockExternalSharing",
                }:
                    # SharePoint/OneDrive: SPO tenant settings (cached)
                    if control_id in {"OneDriveBlockSyncUnmanagedDevices", "SharePointGuestUsersCannotReshare"}:
                        admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                        admin_url = (admin_url or "").strip()

                        if not admin_url:
                            state = "NOT_EVALUATED"
                            details = {"missingKeys": ["spoAdminUrl"]}
                            reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                            reason_detail = "spoAdminUrl not set in tenant config; cannot run SPO tenant settings detector."
                        else:
                            spo = get_spo_tenant_settings_cached(admin_url)
                            f["fallbackDetector"] = {"name": "spo_tenant_settings", "result": spo}

                            if not spo.get("ok"):
                                state = "NOT_EVALUATED"
                                details = {"error": spo.get("error"), "raw": spo}
                                reason_code = "CUSTOM_DETECTOR_ERROR"
                                reason_detail = "SPO tenant settings detector failed (SPO PowerShell)."
                            else:
                                t = (spo.get("tenant") or {})
                                if control_id == "SharePointGuestUsersCannotReshare":
                                    state, details = normalize_detector_result(
                                        detect_sharepoint_guest_users_cannot_reshare(t)
                                    )
                                    reason_code = "CUSTOM_DETECTOR_EVALUATED"
                                    reason_detail = "Evaluated via SPO tenant setting PreventExternalUsersFromResharing."
                                else:
                                    state, details = normalize_detector_result(
                                        detect_onedrive_block_sync_unmanaged_devices(t)
                                    )
                                    reason_code = "CUSTOM_DETECTOR_EVALUATED"
                                    reason_detail = "Evaluated via SPO tenant sync restriction settings (TenantSyncClientRestriction / SyncClientRestrictionEnabled fallback)."

                    # Sway: admin center settings API (best-effort + explicit failure surfacing)
                    elif control_id == "SwayBlockExternalSharing":
                        state, details = normalize_detector_result(
                            detect_sway_block_external_sharing(tenant)
                        )
                        reason_code = "CUSTOM_DETECTOR_EVALUATED" if state in ("COMPLIANT", "DRIFTED") else (details.get("reasonCode") or "CUSTOM_DETECTOR_ERROR")
                        reason_detail = "Evaluated via Sway tenant settings (Microsoft 365 admin center settings API)." if state in ("COMPLIANT", "DRIFTED") else (details.get("reasonDetail") or "Sway settings could not be evaluated.")

                    f["details"] = details

                    audit_path = _write_audit_event_timed(tenant_name, {
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": "detect-only",
                        "status": 200,
                        "details": details,
                        "reason": reason_detail,
                        "reasonCode": reason_code,
                    })
                    print(f"DETECT-ONLY: {control_id} | state={state}")
                    print(f"Audit saved: {audit_path}")
                    continue
                if control_id in {
                    "TeamsAutoAdmitInvitedOnly",
                    "TeamsDesignatedPresenterConfigured",
                    "TeamsLimitExternalControl",
                    "TeamsRestrictAnonymousJoin",
                    "TeamsRestrictAnonymousStartMeeting",
                    "TeamsRestrictDialInBypassLobby",
                }:

                    if not tenant_id or not app_id or not thumb:
                        state = "NOT_EVALUATED"
                        details = {
                            "missingConfig": {
                                "tenant_id": (tenant_id is None),
                                "appId": (app_id is None),
                                "certificateThumbprint": (thumb is None),
                            }
                        }
                        reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                        reason_detail = (
                            "Teams meeting policy detector requires app-only auth config: "
                            "(teamsPowershell|exoPowershell).appId + certificateThumbprint (+ tenantId/auth)."
                        )
                    else:
                        teams_meeting = get_teams_meeting_policies_cached(tenant)


                        if not teams_meeting.get("ok"):
                            state = "NOT_EVALUATED"
                            details = {"error": teams_meeting.get("error"), "raw": teams_meeting}
                            reason_code = "CUSTOM_DETECTOR_ERROR"
                            reason_detail = "Teams meeting policy detector failed (MicrosoftTeams PowerShell)."
                        else:
                            if control_id == "TeamsAutoAdmitInvitedOnly":
                                state, details = normalize_detector_result(
                                    detect_teams_auto_admit_invited_only_status(teams_meeting)
                                )
                            elif control_id == "TeamsDesignatedPresenterConfigured":
                                state, details = normalize_detector_result(
                                    detect_teams_designated_presenter_configured_status(teams_meeting)
                                )
                            elif control_id == "TeamsLimitExternalControl":
                                state, details = normalize_detector_result(
                                    detect_teams_limit_external_control_status(teams_meeting)
                                )
                            elif control_id == "TeamsRestrictAnonymousJoin":
                                state, details = normalize_detector_result(
                                    detect_teams_restrict_anonymous_join_status(teams_meeting)
                                )
                            elif control_id == "TeamsRestrictAnonymousStartMeeting":
                                state, details = normalize_detector_result(
                                    detect_teams_restrict_anonymous_start_meeting_status(teams_meeting)
                                )

                            elif control_id == "TeamsRestrictDialInBypassLobby":
                                state, details = normalize_detector_result(
                                    detect_teams_restrict_dialin_bypass_lobby_status(teams_meeting)
                                )

                            reason_code = "CUSTOM_DETECTOR_EVALUATED"
                            reason_detail = "Evaluated via Teams meeting policies (Get-CsTeamsMeetingPolicy)."

                        f["details"] = details

                # If Secure Score can't evaluate it, make the outcome explicit and customer-safe:
                # We will implement service/API-based fallback detectors for these controls.
                # If Secure Score can't evaluate it, try fallback detectors where implemented.
                # Otherwise, mark as planned but not implemented yet.
                if (control_id in FALLBACK_DETECTORS_PLANNED) and (reason_code == "SECURE_SCORE_ID_MISSING" or not (control.get("secureScoreControlIds") or [])):


                    # SharePoint / OneDrive fallback (IMPLEMENTED)
                    if control_id in {
                        "SharePointDefaultLinkTypeRestricted",
                        "SharePointDefaultSharingRestricted",
                        "SharePointLinkExpirationConfigured",
                        "SharePointIdleSessionTimeout",
                        "SharePointDomainRestrictionConfigured",
                        "SharePointSharingAllowedDomainListConfigured",
                        "SharePointSharingBlockedDomainListConfigured",
                        "SharePointPreventExternalUsersFromResharingEnabled",
                        "OneDriveExternalSharingRestricted",
                        "SharePointIdleSessionTimeout",
                        "OneDriveSyncRestricted",
                    }:
                        admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                        admin_url = (admin_url or "").strip()

                        if not admin_url:
                            reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                            reason_detail = "Secure Score not exposed and spoAdminUrl not set in tenant config; cannot run SPO fallback detector"
                            state = "NOT_EVALUATED"
                        else:

                            spo = get_spo_tenant_settings_cached(admin_url)

                            f["fallbackDetector"] = {"name": "spo_tenant_settings", "result": spo}

                            if not spo.get("ok"):
                                reason_code = "FALLBACK_DETECTOR_ERROR"
                                reason_detail = f"SPO fallback detector failed: {spo.get('error')}"
                                state = "NOT_EVALUATED"
                            else:
                                t = (spo.get("tenant") or {})

                                # Evaluate per-control (conservative defaults)
                                if control_id == "SharePointLinkExpirationConfigured":
                                    days = t.get("RequireAnonymousLinksExpireInDays")

                                    # Expect int. -1/0 means no expiration configured.
                                    f["details"] = {"RequireAnonymousLinksExpireInDays": days}
                                    state = "COMPLIANT" if isinstance(days, int) and days > 0 else "DRIFTED"


                                elif control_id == "SharePointIdleSessionTimeout":
                                    enabled = t.get("IdleSessionSignOutEnabled")
                                    warn_after = t.get("IdleSessionSignOutWarnAfterSeconds")
                                    sign_out_after = t.get("IdleSessionSignOutAfterSeconds")

                                    f["details"] = {
                                        "IdleSessionSignOutEnabled": enabled,
                                        "IdleSessionSignOutWarnAfterSeconds": warn_after,
                                        "IdleSessionSignOutAfterSeconds": sign_out_after,
                                    }

                                    # Conservative compliance: require Enabled AND both timers present AND SignOutAfter > WarnAfter
                                    if enabled is True and isinstance(warn_after, int) and isinstance(sign_out_after, int) and sign_out_after > warn_after and warn_after > 0:
                                        state = "COMPLIANT"
                                    else:
                                        state = "DRIFTED"
                                elif control_id == "SharePointIdleSessionTimeout":
                                    enabled = t.get("IdleSessionSignOutEnabled")
                                    warn_s = t.get("IdleSessionSignOutWarnAfterSeconds")
                                    signout_s = t.get("IdleSessionSignOutAfterSeconds")

                                    f["details"] = {
                                        "IdleSessionSignOutEnabled": enabled,
                                        "IdleSessionSignOutWarnAfterSeconds": warn_s,
                                        "IdleSessionSignOutAfterSeconds": signout_s,
                                    }

                                    missing = []
                                    if enabled is None:
                                        missing.append("IdleSessionSignOutEnabled")
                                    if warn_s is None:
                                        missing.append("IdleSessionSignOutWarnAfterSeconds")
                                    if signout_s is None:
                                        missing.append("IdleSessionSignOutAfterSeconds")

                                    if missing:
                                        state = "NOT_EVALUATED"
                                        reason_code = "MISSING_DATA"
                                        f["details"]["missingKeys"] = missing
                                    else:
                                        # Normalize enabled
                                        enabled_norm = enabled if isinstance(enabled, bool) else str(enabled).strip().lower() in ("true", "1", "yes")
                                        f["details"]["IdleSessionSignOutEnabled_normalized"] = enabled_norm

                                        # Conservative numeric validation
                                        ok_nums = isinstance(warn_s, int) and isinstance(signout_s, int) and warn_s > 0 and signout_s > warn_s
                                        f["details"]["IdleSessionSignOutNumbersValid"] = ok_nums

                                        state = "COMPLIANT" if (enabled_norm and ok_nums) else "DRIFTED"

                                elif control_id == "SharePointDefaultLinkTypeRestricted":
                                    link_type = t.get("DefaultSharingLinkType")

                                    # SharingLinkType enum order: None=0, Direct=1, Internal=2, AnonymousAccess=3
                                    link_type_name = None
                                    if isinstance(link_type, int):
                                        link_type_name = {0: "none", 1: "direct", 2: "internal", 3: "anonymousaccess"}.get(link_type)

                                    f["details"] = {
                                        "DefaultSharingLinkType": link_type,
                                        "DefaultSharingLinkTypeName": link_type_name or str(link_type).lower()
                                    }

                                    # Compliant if NOT "Anyone/AnonymousAccess" AND is explicitly Direct/Internal.
                                    # Conservative: require Direct or Internal (numeric 1 or 2).
                                    if isinstance(link_type, int):
                                        state = "COMPLIANT" if link_type in (1, 2) else "DRIFTED"
                                    else:
                                        state = "COMPLIANT" if str(link_type).strip().lower() in ("direct", "internal") else "DRIFTED"

                                elif control_id == "SharePointDefaultSharingRestricted":
                                    perm = t.get("DefaultLinkPermission")

                                    # SharingPermissionType enum order: None=0, View=1, Edit=2
                                    perm_name = None
                                    if isinstance(perm, int):
                                        perm_name = {0: "none", 1: "view", 2: "edit"}.get(perm)

                                    f["details"] = {
                                        "DefaultLinkPermission": perm,
                                        "DefaultLinkPermissionName": perm_name or str(perm).lower()
                                    }

                                    # Compliant only if default permission is View (not Edit).
                                    if isinstance(perm, int):
                                        state = "COMPLIANT" if perm == 1 else "DRIFTED"
                                    else:
                                        state = "COMPLIANT" if str(perm).strip().lower() == "view" else "DRIFTED"

                                    # Always define sharing safely
                                    sharing = t.get("OneDriveSharingCapability")

                                    if sharing is None:
                                        sharing = t.get("SharingCapability")

                                    f["details"] = {
                                        "OneDriveSharingCapability": t.get("OneDriveSharingCapability"),
                                        "SharingCapability": t.get("SharingCapability"),
                                        "effectiveSharingCapability": sharing,
                                    }

                                    s = str(sharing).lower() if sharing is not None else ""

                                    # Restricted = NOT guest / anyone sharing
                                    state = "COMPLIANT" if s in (
                                        "disabled",
                                        "existingexternaluser",
                                        "externaluser"
                                    ) else "DRIFTED"

                                elif control_id == "SharePointDomainRestrictionConfigured":
                                    mode = t.get("SharingDomainRestrictionMode")
                                    f["details"] = {
                                        "SharingDomainRestrictionMode": mode,
                                    }

                                    if mode is None:
                                        state = "NOT_EVALUATED"
                                        reason_code = "MISSING_DATA"
                                        f["details"]["missingKeys"] = ["SharingDomainRestrictionMode"]
                                    else:
                                        mode_norm = str(mode).strip()
                                        f["details"]["SharingDomainRestrictionMode_normalized"] = mode_norm

                                        # COMPLIANT if allow/block list mode is configured (not None)
                                        state = "COMPLIANT" if mode_norm.lower() not in ("none", "", "0") else "DRIFTED"

                                elif control_id == "SharePointSharingAllowedDomainListConfigured":
                                    mode = t.get("SharingDomainRestrictionMode")
                                    allowed_raw = t.get("SharingAllowedDomainList")

                                    f["details"] = {
                                        "SharingDomainRestrictionMode": mode,
                                        "SharingAllowedDomainList_raw": allowed_raw,
                                    }

                                    missing = []
                                    if mode is None:
                                        missing.append("SharingDomainRestrictionMode")
                                    if allowed_raw is None:
                                        missing.append("SharingAllowedDomainList")

                                    if missing:
                                        state = "NOT_EVALUATED"
                                        reason_code = "MISSING_DATA"
                                        f["details"]["missingKeys"] = missing
                                    else:
                                        mode_norm = str(mode).strip()
                                        allowed_str = str(allowed_raw).strip()

                                        # Conservative parse: split by comma/semicolon/newlines; remove empties
                                        parts = [p.strip() for p in allowed_str.replace(";", ",").replace("\n", ",").split(",")]
                                        allowed = [p for p in parts if p]

                                        f["details"]["SharingDomainRestrictionMode_normalized"] = mode_norm
                                        f["details"]["SharingAllowedDomainList_normalized"] = allowed

                                        if mode_norm.lower() != "allowlist":
                                            state = "DRIFTED"
                                            f["details"]["note"] = "Domain restriction mode is not AllowList; allowed domain list is not effectively configured."
                                        else:
                                            state = "COMPLIANT" if len(allowed) > 0 else "DRIFTED"
                                            if len(allowed) == 0:
                                                f["details"]["note"] = "AllowList mode is set but allowed domain list is empty."

                                elif control_id == "SharePointSharingBlockedDomainListConfigured":
                                    mode = t.get("SharingDomainRestrictionMode")
                                    blocked_raw = t.get("SharingBlockedDomainList")

                                    f["details"] = {
                                        "SharingDomainRestrictionMode": mode,
                                        "SharingBlockedDomainList_raw": blocked_raw,
                                    }

                                    missing = []
                                    if mode is None:
                                        missing.append("SharingDomainRestrictionMode")
                                    if blocked_raw is None:
                                        missing.append("SharingBlockedDomainList")

                                    if missing:
                                        state = "NOT_EVALUATED"
                                        reason_code = "MISSING_DATA"
                                        f["details"]["missingKeys"] = missing
                                    else:
                                        mode_norm = str(mode).strip()
                                        blocked_str = str(blocked_raw).strip()

                                        # Conservative parse: split by comma/semicolon/newlines; remove empties
                                        parts = [p.strip() for p in blocked_str.replace(";", ",").replace("\n", ",").split(",")]
                                        blocked = [p for p in parts if p]

                                        f["details"]["SharingDomainRestrictionMode_normalized"] = mode_norm
                                        f["details"]["SharingBlockedDomainList_normalized"] = blocked

                                        if mode_norm.lower() != "blocklist":
                                            state = "DRIFTED"
                                            f["details"]["note"] = "Domain restriction mode is not BlockList; blocked domain list is not effectively configured."
                                        else:
                                            state = "COMPLIANT" if len(blocked) > 0 else "DRIFTED"
                                            if len(blocked) == 0:
                                                f["details"]["note"] = "BlockList mode is set but blocked domain list is empty."

                                elif control_id == "SharePointPreventExternalUsersFromResharingEnabled":
                                    val = t.get("PreventExternalUsersFromResharing")
                                    f["details"] = {"PreventExternalUsersFromResharing": val}

                                    if val is None:
                                        state = "NOT_EVALUATED"
                                        reason_code = "MISSING_DATA"
                                        f["details"]["missingKeys"] = ["PreventExternalUsersFromResharing"]
                                    else:
                                        if isinstance(val, bool):
                                            enabled = val
                                        else:
                                            enabled = str(val).strip().lower() in ("true", "1", "yes")
                                        f["details"]["PreventExternalUsersFromResharing_normalized"] = enabled
                                        state = "COMPLIANT" if enabled else "DRIFTED"


                                elif control_id == "OneDriveSyncRestricted":
                                    # "Allow syncing only on computers joined to specific domains"
                                    enabled = t.get("SyncClientRestrictionEnabled")
                                    allowed = t.get("AllowedDomainGuids")

                                elif control_id == "OneDriveExternalSharingRestricted":
                                    # Prefer OneDriveSharingCapability when present, fallback to tenant SharingCapability
                                    one_drive_cap = t.get("OneDriveSharingCapability")
                                    tenant_cap = t.get("SharingCapability")

                                    effective = one_drive_cap if isinstance(one_drive_cap, int) else tenant_cap

                                    f["details"] = {
                                        "OneDriveSharingCapability": one_drive_cap,
                                        "SharingCapability": tenant_cap,
                                        "effectiveSharingCapability": effective,
                                    }

                                    # Conservative: COMPLIANT only if external sharing is effectively disabled (0) or internal-only (1)
                                    # Observed values: 2 means external sharing allowed -> DRIFTED
                                    if isinstance(effective, int):
                                        state = "COMPLIANT" if effective in (0, 1) else "DRIFTED"
                                    else:
                                        state = "DRIFTED"

                                

                                reason_code = "FALLBACK_DETECTOR_EVALUATED"
                                reason_detail = "Secure Score not exposed; evaluated via SharePoint tenant settings (SPO PowerShell)"


                    # Teams fallback (IMPLEMENTED)
                    elif control_id in {
                        # Tenant settings controls
                        "TeamsExternalAccessRestricted",
                        "TeamsFederationRestricted",
                        "TeamsFileSharingRestricted",

                        # Meeting policy controls (Batch A)
                        "TeamsAutoAdmitInvitedOnly",
                        "TeamsDesignatedPresenterConfigured",
                        "TeamsLimitExternalControl",
                        "TeamsRestrictAnonymousJoin",
                        "TeamsRestrictAnonymousStartMeeting",
                        "TeamsRestrictDialInBypassLobby",
                    }:
                        # First: validate we have Teams PowerShell auth (same requirements for both tenant + meeting calls)
                        tenant_id, app_id, thumb = _get_teams_ps_auth_from_tenant(tenant)
                        if not (tenant_id and app_id and thumb):
                            reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                            reason_detail = "Teams fallback requires auth.tenant_id and (teamsPowershell|exoPowershell).appId + certificateThumbprint"
                            state = "NOT_EVALUATED"

                        else:
                            # --- Meeting policy controls (Batch A) ---
                            if control_id in {
                                "TeamsAutoAdmitInvitedOnly",
                                "TeamsDesignatedPresenterConfigured",
                                "TeamsLimitExternalControl",
                                "TeamsRestrictAnonymousJoin",
                                "TeamsRestrictAnonymousStartMeeting",
                                "TeamsRestrictDialInBypassLobby",
                            }:
                                meeting = get_teams_meeting_policies_cached(tenant)
                                f["fallbackDetector"] = {"name": "teams_meeting_policies", "result": meeting}

                                if not meeting.get("ok"):
                                    err = (meeting.get("error") or "").lower()
                                    state = "NOT_EVALUATED"

                                    if "module is not installed" in err or "install-module microsofteams" in err:
                                        reason_code = "FALLBACK_DETECTOR_PREREQ_MISSING"
                                        reason_detail = "Teams meeting policy fallback requires MicrosoftTeams PowerShell module on the runner host."
                                    else:
                                        reason_code = "FALLBACK_DETECTOR_ERROR"
                                        reason_detail = f"Teams meeting policy fallback failed: {meeting.get('error')}"
                                else:
                                    # Call the correct detector (they return {state, details, reasonCode, reasonDetail})
                                    if control_id == "TeamsAutoAdmitInvitedOnly":
                                        out = detect_teams_auto_admit_invited_only_status(meeting)
                                    elif control_id == "TeamsDesignatedPresenterConfigured":
                                        out = detect_teams_designated_presenter_configured_status(meeting)
                                    elif control_id == "TeamsLimitExternalControl":
                                        out = detect_teams_limit_external_control_status(meeting)
                                    elif control_id == "TeamsRestrictAnonymousJoin":
                                        out = detect_teams_restrict_anonymous_join_status(meeting)
                                    elif control_id == "TeamsRestrictAnonymousStartMeeting":
                                        out = detect_teams_restrict_anonymous_start_meeting_status(meeting)
                                    elif control_id == "TeamsRestrictDialInBypassLobby":
                                        out = detect_teams_restrict_dialin_bypass_lobby_status(meeting)
                                    else:
                                        out = {
                                            "state": "NOT_EVALUATED",
                                            "details": {"error": "No detector mapped"},
                                            "reasonCode": "MISSING_DATA",
                                            "reasonDetail": "No detector mapped",
                                        }

                                    state = out.get("state") or "NOT_EVALUATED"
                                    f["details"] = out.get("details") or {}
                                    reason_code = out.get("reasonCode") or "FALLBACK_DETECTOR_EVALUATED"
                                    reason_detail = out.get("reasonDetail") or "Evaluated via Teams meeting policy (MicrosoftTeams PowerShell)"

                            # --- Tenant settings controls (existing) ---
                            else:
                                teams = get_teams_tenant_settings_cached(tenant)
                                f["fallbackDetector"] = {"name": "teams_tenant_settings", "result": teams}

                                if not teams.get("ok"):
                                    err = (teams.get("error") or "").lower()
                                    state = "NOT_EVALUATED"

                                    if "module is not installed" in err or "install-module microsofteams" in err:
                                        reason_code = "FALLBACK_DETECTOR_PREREQ_MISSING"
                                        reason_detail = "Teams tenant settings fallback requires MicrosoftTeams PowerShell module on the runner host."
                                    else:
                                        reason_code = "FALLBACK_DETECTOR_ERROR"
                                        reason_detail = f"Teams tenant settings fallback failed: {teams.get('error')}"

                                else:
                                    t = (teams.get("tenant") or {})
                                    fed = (t.get("Federation") or {})

                                    if control_id == "TeamsFederationRestricted":
                                        enabled = fed.get("AllowFederatedUsers")

                                        allowed_raw = fed.get("AllowedDomains") or fed.get("AllowedDomainsAsAList") or []
                                        allowed = []

                                        if isinstance(allowed_raw, list):
                                            allowed = [str(x).strip() for x in allowed_raw if str(x).strip()]
                                        elif isinstance(allowed_raw, str):
                                            allowed = [x.strip() for x in allowed_raw.split(",") if x.strip()]

                                        f["details"] = {
                                            "AllowFederatedUsers": enabled,
                                            "AllowedDomains": allowed,
                                            "AllowedDomainsCount": len(allowed),
                                        }

                                        state = "COMPLIANT" if (enabled in (False, "False") or len(allowed) > 0) else "DRIFTED"

                                    elif control_id == "TeamsExternalAccessRestricted":
                                        enabled = fed.get("AllowFederatedUsers")

                                        allowed_raw = fed.get("AllowedDomains")
                                        allowed = []
                                        if isinstance(allowed_raw, list):
                                            allowed = [str(x).strip() for x in allowed_raw if str(x).strip()]
                                        elif isinstance(allowed_raw, str):
                                            allowed = [x.strip() for x in allowed_raw.split(",") if x.strip()]
                                        else:
                                            allowed = []

                                        f["details"] = {
                                            "AllowFederatedUsers": enabled,
                                            "AllowedDomains": allowed,
                                            "AllowedDomainsCount": len(allowed),
                                            "ExternalAccessPolicy": t.get("ExternalAccessPolicy"),
                                        }

                                        state = "COMPLIANT" if (enabled in (False, "False") or len(allowed) > 0) else "DRIFTED"
                                        reason_code = "FALLBACK_DETECTOR_EVALUATED"
                                        reason_detail = "Secure Score not exposed; evaluated via Teams tenant settings (Teams PowerShell)"

                                    elif control_id == "TeamsFileSharingRestricted":
                                        admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                                        admin_url = (admin_url or "").strip()

                                        if not admin_url:
                                            reason_code = "FALLBACK_DETECTOR_CONFIG_MISSING"
                                            reason_detail = "Teams file sharing posture requires spoAdminUrl to evaluate SharePoint/OneDrive sharing settings"
                                            state = "NOT_EVALUATED"
                                        else:
                                            spo = get_spo_tenant_settings_cached(admin_url)
                                            f.setdefault("fallbackDetectorChain", []).append({"name": "spo_tenant_settings", "result": spo})

                                            if not spo.get("ok"):
                                                reason_code = "FALLBACK_DETECTOR_ERROR"
                                                reason_detail = f"SPO fallback detector failed: {spo.get('error')}"
                                                state = "NOT_EVALUATED"
                                            else:
                                                st = (spo.get("tenant") or {})
                                                sharing = st.get("OneDriveSharingCapability")
                                                if sharing is None:
                                                    sharing = st.get("SharingCapability")

                                                s = str(sharing).lower()
                                                f["details"] = {
                                                    "OneDriveSharingCapability": st.get("OneDriveSharingCapability"),
                                                    "SharingCapability": st.get("SharingCapability"),
                                                    "effectiveSharingCapability": sharing,
                                                }
                                                state = "COMPLIANT" if s in ("disabled", "existingexternaluser", "externaluser") else "DRIFTED"

                                    if state != "NOT_EVALUATED" and reason_code is None:
                                        reason_code = "FALLBACK_DETECTOR_EVALUATED"
                                        reason_detail = "Secure Score not exposed; evaluated via Teams tenant settings (Teams PowerShell)"

                    # Everything else in FALLBACK_DETECTORS_PLANNED is still planned (NOT IMPLEMENTED)
                    else:
                        reason_code = "FALLBACK_DETECTOR_NOT_IMPLEMENTED_YET"
                        reason_detail = "Secure Score not exposed for this tenant; fallback detector is planned but not implemented yet"
                        state = "NOT_EVALUATED"

                        # SharePoint / OneDrive fallback
                        if control_id in {
                            "SharePointDefaultLinkTypeRestricted",
                            "SharePointDefaultSharingRestricted",
                            "SharePointLinkExpirationConfigured",
                            "SharePointDomainRestrictionConfigured",
                            "SharePointSharingAllowedDomainListConfigured",
                            "SharePointIdleSessionTimeout",
                            "SharePointSharingBlockedDomainListConfigured",
                            "SharePointPreventExternalUsersFromResharingEnabled",
                            "OneDriveExternalSharingRestricted",
                            "OneDriveSyncRestricted",
                        }:
                            admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
                            admin_url = (admin_url or "").strip()

                            if not admin_url:
                                reason_detail = "Secure Score not exposed and spoAdminUrl not set in tenant config; cannot run SPO fallback detector"
                            else:
                                spo = get_spo_tenant_settings_cached(admin_url)


                                f["fallbackDetector"] = {"name": "spo_tenant_settings", "result": spo}

                                if not spo.get("ok"):
                                    reason_detail = f"SPO fallback detector failed: {spo.get('error')}"
                                else:
                                    t = (spo.get("tenant") or {})

                                    # Evaluate per-control (conservative defaults)
                                    if control_id == "SharePointLinkExpirationConfigured":
                                        days = t.get("RequireAnonymousLinksExpireInDays")

                                        # Expect int. -1/0 means no expiration configured.
                                        f["details"] = {"RequireAnonymousLinksExpireInDays": days}
                                        state = "COMPLIANT" if isinstance(days, int) and days > 0 else "DRIFTED"

                                    elif control_id == "SharePointDefaultLinkTypeRestricted":
                                        link_type = t.get("DefaultSharingLinkType")

                                        # SharingLinkType enum order: None=0, Direct=1, Internal=2, AnonymousAccess=3
                                        link_type_name = None
                                        if isinstance(link_type, int):
                                            link_type_name = {0: "none", 1: "direct", 2: "internal", 3: "anonymousaccess"}.get(link_type)

                                        f["details"] = {
                                            "DefaultSharingLinkType": link_type,
                                            "DefaultSharingLinkTypeName": link_type_name or str(link_type).lower()
                                        }

                                        # Compliant if NOT "Anyone/AnonymousAccess" AND is explicitly Direct/Internal.
                                        # Conservative: require Direct or Internal (numeric 1 or 2).
                                        if isinstance(link_type, int):
                                            state = "COMPLIANT" if link_type in (1, 2) else "DRIFTED"
                                        else:
                                            state = "COMPLIANT" if str(link_type).strip().lower() in ("direct", "internal") else "DRIFTED"

                                    elif control_id == "SharePointDefaultSharingRestricted":
                                        perm = t.get("DefaultLinkPermission")

                                        # SharingPermissionType enum order: None=0, View=1, Edit=2
                                        perm_name = None
                                        if isinstance(perm, int):
                                            perm_name = {0: "none", 1: "view", 2: "edit"}.get(perm)

                                        f["details"] = {
                                            "DefaultLinkPermission": perm,
                                            "DefaultLinkPermissionName": perm_name or str(perm).lower()
                                        }

                                        # Compliant only if default permission is View (not Edit).
                                        if isinstance(perm, int):
                                            state = "COMPLIANT" if perm == 1 else "DRIFTED"
                                        else:
                                            state = "COMPLIANT" if str(perm).strip().lower() == "view" else "DRIFTED"

                                        # Always define sharing safely
                                        sharing = t.get("OneDriveSharingCapability")

                                        if sharing is None:
                                            sharing = t.get("SharingCapability")

                                        f["details"] = {
                                            "OneDriveSharingCapability": t.get("OneDriveSharingCapability"),
                                            "SharingCapability": t.get("SharingCapability"),
                                            "effectiveSharingCapability": sharing,
                                        }

                                        s = str(sharing).lower() if sharing is not None else ""

                                        # Restricted = NOT guest / anyone sharing
                                        state = "COMPLIANT" if s in (
                                            "disabled",
                                            "existingexternaluser",
                                            "externaluser"
                                        ) else "DRIFTED"



                                        f["details"] = {
                                            "OneDriveSharingCapability": t.get("OneDriveSharingCapability"),
                                            "SharingCapability": t.get("SharingCapability"),
                                            "effectiveSharingCapability": sharing,
                                        }

                                        # Conservative: restricted means NOT guest/anyone sharing
                                        # (Common values seen: Disabled / ExistingExternalUser / ExternalUser / ExternalUserAndGuestSharing)
                                        s = str(sharing).lower()
                                        if s in ("disabled", "existingexternaluser", "externaluser"):
                                            state = "COMPLIANT"
                                        else:
                                            state = "DRIFTED"

                                        reason_code = "FALLBACK_DETECTOR_EVALUATED"
                                        reason_detail = "Evaluated via SharePoint Online tenant settings (OneDrive sharing capability)."
                                    # --- DUPLICATE SPO DOMAIN CONTROLS EVALUATOR (disabled) ---
                                    # This block is a duplicate of the earlier SPO domain restriction evaluator.
                                    # Disabled to avoid divergence. Do not remove unless you confirm nothing references it.
                                    """
                                    elif control_id == "SharePointDomainRestrictionConfigured":
                                        mode = t.get("SharingDomainRestrictionMode")
                                        f["details"] = {
                                            "SharingDomainRestrictionMode": mode,
                                        }

                                        if mode is None:
                                            state = "NOT_EVALUATED"
                                            reason_code = "MISSING_DATA"
                                            f["details"]["missingKeys"] = ["SharingDomainRestrictionMode"]
                                        else:
                                            mode_norm = str(mode).strip()
                                            f["details"]["SharingDomainRestrictionMode_normalized"] = mode_norm

                                            # COMPLIANT if allow/block list mode is configured (not None)
                                            state = "COMPLIANT" if mode_norm.lower() not in ("none", "", "0") else "DRIFTED"

                                    elif control_id == "SharePointSharingAllowedDomainListConfigured":
                                        mode = t.get("SharingDomainRestrictionMode")
                                        allowed_raw = t.get("SharingAllowedDomainList")

                                        f["details"] = {
                                            "SharingDomainRestrictionMode": mode,
                                            "SharingAllowedDomainList_raw": allowed_raw,
                                        }

                                        missing = []
                                        if mode is None:
                                            missing.append("SharingDomainRestrictionMode")
                                        if allowed_raw is None:
                                            missing.append("SharingAllowedDomainList")

                                        if missing:
                                            state = "NOT_EVALUATED"
                                            reason_code = "MISSING_DATA"
                                            f["details"]["missingKeys"] = missing
                                        else:
                                            mode_norm = str(mode).strip()
                                            allowed_str = str(allowed_raw).strip()

                                            # Conservative parse: split by comma/semicolon/newlines; remove empties
                                            parts = [p.strip() for p in allowed_str.replace(";", ",").replace("\n", ",").split(",")]
                                            allowed = [p for p in parts if p]

                                            f["details"]["SharingDomainRestrictionMode_normalized"] = mode_norm
                                            f["details"]["SharingAllowedDomainList_normalized"] = allowed

                                            if mode_norm.lower() != "allowlist":
                                                state = "DRIFTED"
                                                f["details"]["note"] = "Domain restriction mode is not AllowList; allowed domain list is not effectively configured."
                                            else:
                                                state = "COMPLIANT" if len(allowed) > 0 else "DRIFTED"
                                                if len(allowed) == 0:
                                                    f["details"]["note"] = "AllowList mode is set but allowed domain list is empty."

                                    elif control_id == "SharePointSharingBlockedDomainListConfigured":
                                        mode = t.get("SharingDomainRestrictionMode")
                                        blocked_raw = t.get("SharingBlockedDomainList")

                                        f["details"] = {
                                            "SharingDomainRestrictionMode": mode,
                                            "SharingBlockedDomainList_raw": blocked_raw,
                                        }

                                        missing = []
                                        if mode is None:
                                            missing.append("SharingDomainRestrictionMode")
                                        if blocked_raw is None:
                                            missing.append("SharingBlockedDomainList")

                                        if missing:
                                            state = "NOT_EVALUATED"
                                            reason_code = "MISSING_DATA"
                                            f["details"]["missingKeys"] = missing
                                        else:
                                            mode_norm = str(mode).strip()
                                            blocked_str = str(blocked_raw).strip()

                                            # Conservative parse: split by comma/semicolon/newlines; remove empties
                                            parts = [p.strip() for p in blocked_str.replace(";", ",").replace("\n", ",").split(",")]
                                            blocked = [p for p in parts if p]

                                            f["details"]["SharingDomainRestrictionMode_normalized"] = mode_norm
                                            f["details"]["SharingBlockedDomainList_normalized"] = blocked

                                            if mode_norm.lower() != "blocklist":
                                                state = "DRIFTED"
                                                f["details"]["note"] = "Domain restriction mode is not BlockList; blocked domain list is not effectively configured."
                                            else:
                                                state = "COMPLIANT" if len(blocked) > 0 else "DRIFTED"
                                                if len(blocked) == 0:
                                                    f["details"]["note"] = "BlockList mode is set but blocked domain list is empty."
                                    """
                                    if control_id == "SharePointPreventExternalUsersFromResharingEnabled":
                                        val = t.get("PreventExternalUsersFromResharing")
                                        f["details"] = {"PreventExternalUsersFromResharing": val}

                                        if val is None:
                                            state = "NOT_EVALUATED"
                                            reason_code = "MISSING_DATA"
                                            f["details"]["missingKeys"] = ["PreventExternalUsersFromResharing"]
                                        else:
                                            if isinstance(val, bool):
                                                enabled = val
                                            else:
                                                enabled = str(val).strip().lower() in ("true", "1", "yes")
                                            f["details"]["PreventExternalUsersFromResharing_normalized"] = enabled
                                            state = "COMPLIANT" if enabled else "DRIFTED"

                                    elif control_id == "OneDriveSyncRestricted":
                                        # "Allow syncing only on computers joined to specific domains"
                                        enabled = t.get("SyncClientRestrictionEnabled")
                                        allowed = t.get("AllowedDomainGuids")
                                    elif control_id == "TeamsAutoAdmitInvitedOnly":
                                        state, details = detect_teams_auto_admit_invited_only_status(teams_meeting)
                                        f["details"] = details
                                        reason_code = "CUSTOM_DETECTOR_EVALUATED"
                                        reason_detail = "Evaluated via Teams meeting policies (Get-CsTeamsMeetingPolicy)."

                                    elif control_id == "TeamsDesignatedPresenterConfigured":
                                        state, details = detect_teams_designated_presenter_configured_status(teams_meeting)
                                        f["details"] = details
                                        reason_code = "CUSTOM_DETECTOR_EVALUATED"
                                        reason_detail = "Evaluated via Teams meeting policies (Get-CsTeamsMeetingPolicy)."

                                    elif control_id == "TeamsLimitExternalControl":
                                        state, details = detect_teams_limit_external_control_status(teams_meeting)
                                        f["details"] = details
                                        reason_code = "CUSTOM_DETECTOR_EVALUATED"
                                        reason_detail = "Evaluated via Teams meeting policies (Get-CsTeamsMeetingPolicy)."

                                    elif control_id == "TeamsRestrictAnonymousJoin":
                                        state, details = detect_teams_restrict_anonymous_join_status(teams_meeting)
                                        f["details"] = details
                                        reason_code = "CUSTOM_DETECTOR_EVALUATED"
                                        reason_detail = "Evaluated via Teams meeting policies (Get-CsTeamsMeetingPolicy)."

                                    elif control_id == "TeamsRestrictAnonymousStartMeeting":
                                        state, details = detect_teams_restrict_anonymous_start_meeting_status(teams_meeting)
                                        f["details"] = details
                                        reason_code = "CUSTOM_DETECTOR_EVALUATED"
                                        reason_detail = "Evaluated via Teams meeting policies (Get-CsTeamsMeetingPolicy)."

                                    elif control_id == "TeamsRestrictDialInBypassLobby":
                                        state, details = detect_teams_restrict_dialin_bypass_lobby_status(teams_meeting)
                                        f["details"] = details
                                        reason_code = "CUSTOM_DETECTOR_EVALUATED"
                                        reason_detail = "Evaluated via Teams meeting policies (Get-CsTeamsMeetingPolicy)."


                                    elif control_id == "OneDriveExternalSharingRestricted":
                                        # Prefer OneDriveSharingCapability when present, fallback to tenant SharingCapability
                                        one_drive_cap = t.get("OneDriveSharingCapability")
                                        tenant_cap = t.get("SharingCapability")

                                        effective = one_drive_cap if isinstance(one_drive_cap, int) else tenant_cap

                                        f["details"] = {
                                            "OneDriveSharingCapability": one_drive_cap,
                                            "SharingCapability": tenant_cap,
                                            "effectiveSharingCapability": effective,
                                        }

                                        # Conservative: COMPLIANT only if external sharing is effectively disabled (0) or internal-only (1)
                                        # Observed values: 2 means external sharing allowed -> DRIFTED
                                        if isinstance(effective, int):
                                            state = "COMPLIANT" if effective in (0, 1) else "DRIFTED"
                                        else:
                                            state = "DRIFTED"


                                    
                                        reason_code = "FALLBACK_DETECTOR_EVALUATED"
                                        reason_detail = "Evaluated via SharePoint Online tenant settings (sync restriction)."
                # Determine effective mode for this matched item (prefer f.mode, else control default)
                mode = f.get("mode") if isinstance(f, dict) else None
                if not mode:
                    mode = control.get("default_mode", "report-only")
                mode = str(mode).strip().lower()

                # Detect-only must route to evaluation/reporting path and must not require a handler
                detect_only = (mode == "detect-only")

                # If Secure Score is missing for this control, that's missing signal, not drift.
                if (details or {}).get("reasonCode") == "SECURE_SCORE_ID_MISSING":
                    return_not_evaluated(
                        write_audit_event=_write_audit_event_timed,
                        tenant_name=tenant_name,
                        control_id=control_id,
                        control=control,
                        mode=mode,
                        approval=approval,
                        reason="Secure Score controlId referenced by ATLAS but missing from this tenant's controlProfiles",
                        details={
                            "reasonCode": "SECURE_SCORE_ID_MISSING",
                            "reasonDetail": "Secure Score controlId referenced by ATLAS but missing from this tenant's controlProfiles",
                            "missingSecureScoreControlIds": (f or {}).get("missingSecureScoreControlIds"),
                            "secureScoreControlId": (f or {}).get("secureScoreControlId"),
                        },

                    )
                    continue

                audit_path = _write_audit_event_timed(
                    tenant_name,
                    attach_reason({
                        "tenant": tenant_name,
                        "controlId": control_id,
                        "action": "detect_only",
                        "state": state,
                        "displayName": control.get("name", control_id),
                        "mode": mode,
                        "status": 200,
                        "scorePct": pct,
                        "missingSecureScoreControlIds": (f or {}).get("missingSecureScoreControlIds"),
                        "secureScoreControlId": f.get("controlId"),
                        "title": f.get("title"),
                        "implementationStatus": f.get("implementationStatus"),
                        "actionUrl": f.get("actionUrl"),
                        "details": details,
                        "fallbackDetector": f.get("fallbackDetector"),
                        "reason": "detect-only registry control (no enforcement implemented)",
                    }, reason_code, reason_detail)
                )
                # If Secure Score is missing for this control, that's missing signal, not drift.
                if reason_code == "SECURE_SCORE_ID_MISSING":
                    return_not_evaluated(
                        write_audit_event=_write_audit_event_timed,
                        tenant_name=tenant_name,
                        control_id=control_id,
                        control=control,
                        mode=mode,
                        approval=approval,
                        reason=reason_detail or "Secure Score controlId referenced by ATLAS but missing from this tenant's controlProfiles",
                        details={
                            "reasonCode": reason_code,
                            "reasonDetail": reason_detail,
                            "missingSecureScoreControlIds": (f or {}).get("missingSecureScoreControlIds"),
                            "secureScoreControlId": (f or {}).get("secureScoreControlId"),
                        },
                    )
                    continue

                print(f"DETECT-ONLY: {control_id} | state={state} | scorePct={pct}")
                print(f"Audit saved: {audit_path}")
                continue

            # Not detect-only and no handler => approved but not implemented / or just missing handler
            audit_path = _write_audit_event_timed(
                tenant_name,
                attach_reason({
                    "tenant": tenant_name,
                    "controlId": control_id,
                    "action": "ensure_skipped_no_handler",
                    "displayName": control.get("name", control_id),
                    "approved": True if approval_required else False,
                    "mode": mode,
                    "status": 501,
                    "reason": "no handler implemented for this control",
                }, "NO_HANDLER_IMPLEMENTED", "no handler implemented for this control")
            )

            print(f"SKIP (no handler yet): {control_id}")
            print(f"Audit saved: {audit_path}")
            continue

    stamp = utc_stamp()
    out_dir = os.path.join("output", "findings", tenant["tenant_name"], stamp)

    write_json(os.path.join(out_dir, "secureScore_latest.json"), score)
    write_json(os.path.join(out_dir, "secureScore_controlProfiles.json"), profiles)
    write_json(os.path.join(out_dir, "findings.json"), findings)
    # --- Persist control timings (evidence + later optimization) ---
    try:
        timings_payload = {
            "tenant": tenant_name,
            "generatedAt": stamp,
            "count": len(_CONTROL_TIMINGS),
            "rows": _CONTROL_TIMINGS,
        }

        # Write canonical file
        write_json(os.path.join(out_dir, "_CONTROL_TIMINGS.json"), timings_payload)

        # Back-compat (some scripts may still look for this name)
        write_json(os.path.join(out_dir, "control_timings.json"), timings_payload)

        # Console: top 10 slowest controls (skip None / non-numeric durations)
        numeric_rows = [
            r for r in _CONTROL_TIMINGS
            if isinstance(r.get("durationSeconds"), (int, float))
        ]

        slowest = sorted(
            numeric_rows,
            key=lambda r: float(r.get("durationSeconds")),
            reverse=True
        )[:10]

        print("\n==== TOP 10 SLOWEST CONTROLS (by durationSeconds) ====\n")
        if not slowest:
            print("  (no timings recorded)")
        else:
            for r in slowest:
                dur = r.get("durationSeconds")
                try:
                    dur_s = f"{float(dur):7.3f}"
                except Exception:
                    dur_s = "   n/a"

                print(
                    f'{dur_s} s | '
                    f'{(r.get("category") or ""):<12} | '
                    f'{(r.get("controlId") or ""):<40} | '
                    f'{(r.get("state") or ""):<12} | '
                    f'{(r.get("reasonCode") or "")}'
                )

    except Exception as e:
        print(f"[WARN] Failed to write timing log: {e}")
    # --- end timings ---


    # quick console summary
    # Only show "gaps" that map to ATLAS registry controls (prevents noise from unrelated Secure Score items)
    atlas_ss_findings = [
        f for f in findings
        if ((f.get("controlId") or "").strip().lower()) in ss_to_registry
        and f.get("scorePct") is not None
        and any(
            not registry_by_id.get(rid, {}).get("gapOnly", False)
            for rid in ss_to_registry.get(((f.get("controlId") or "").strip().lower()), [])
        )
    ]



    # De-dupe by Secure Score controlId (findings can contain duplicates due to multiple registry controls mapping to same SS id)
    dedup_by_control = {}
    for f in atlas_ss_findings:
        cid = f.get("controlId")
        if not cid:
            continue

        # keep the "worst" (lowest) scorePct if we see the same controlId again
        existing = dedup_by_control.get(cid)
        if existing is None or float(f["scorePct"]) < float(existing["scorePct"]):
            dedup_by_control[cid] = f

    atlas_ss_findings_dedup = list(dedup_by_control.values())

    top10 = sorted(
        atlas_ss_findings_dedup,
        key=lambda x: (float(x["scorePct"]), x.get("category") or "", x.get("controlId") or "")
    )[:10]


    print("\n==== TOP 10 SECURE SCORE GAPS (ATLAS-MAPPED ONLY, lowest compliance first) ====\n")
    for f in top10:
        print(f'{f["scorePct"]:>3} | {f.get("category",""):<8} | {f.get("controlId",""):<35} | {f.get("title","")}')
    # Top 10 Secure Score gaps that ATLAS does NOT currently map to any registry control
    unmapped_ss_findings = [
        f for f in findings
        if ((f.get("controlId") or "").strip().lower()) not in ss_to_registry
        and f.get("scorePct") is not None
        and float(f.get("scorePct")) < 100.0
    ]



    # De-dupe by Secure Score controlId just in case
    dedup_unmapped = {}
    for f in unmapped_ss_findings:
        cid = f.get("controlId")
        if not cid:
            continue
        existing = dedup_unmapped.get(cid)
        if existing is None or float(f["scorePct"]) < float(existing["scorePct"]):
            dedup_unmapped[cid] = f

    unmapped_ss_findings_dedup = list(dedup_unmapped.values())

    top10_unmapped = sorted(
        unmapped_ss_findings_dedup,
        key=lambda x: (float(x["scorePct"]), x.get("category") or "", x.get("controlId") or "")
    )[:10]

    print("\n==== TOP 10 SECURE SCORE GAPS (UNMAPPED to ATLAS, lowest compliance first) ====\n")
    if not top10_unmapped:
        print("  (none)")
    else:
        for f in top10_unmapped:
            print(f'{f["scorePct"]:>3} | {f.get("category",""):<8} | {f.get("controlId",""):<35} | {f.get("title","")}')


    # --- End-of-run Tier 3 onboarding summary ---
    if tier3_summary:
        # ==== EXECUTIVE SUMMARY (customer-safe) ====
        # Build Secure Score stats from ATLAS controls (post-overlay)
        atlas_ss_controls = [
            c for c in matched
            if c.get("secureScoreControlIds")
        ]

        atlas_ss_scored = [c for c in atlas_ss_controls if c.get("scorePct") is not None]
        atlas_ss_at100 = [c for c in atlas_ss_scored if float(c.get("scorePct")) >= 100.0]
        atlas_ss_below100 = [c for c in atlas_ss_scored if float(c.get("scorePct")) < 100.0]
        atlas_ss_not_scored = [c for c in atlas_ss_controls if c.get("scorePct") is None]

        # Tier 3 blockers / readiness highlights
        tier3_blocked = [t for t in (tier3_summary or []) if t.get("outcome") == "BLOCKED"]
        tier3_not_ready = [
            t for t in (tier3_summary or [])
            if t.get("controlId") in ("Tier3AuthMethodsReadiness", "Tier3BreakGlassReadiness")
            and t.get("reason") == "NOT_READY"
        ]

        executive_summary = {
            "tenant": tenant_name,
            "generatedAt": stamp,
            "atlas": {
                "totalRegistryControls": len(registry_controls),
                "totalMatchedControls": len(matched),
            },
            "secureScore": {
                "atlasControlsWithSecureScoreMapping": len(atlas_ss_controls),
                "atlasControlsWithScorePct": len(atlas_ss_scored),
                "atlasControlsAt100": len(atlas_ss_at100),
                "atlasControlsBelow100": len(atlas_ss_below100),
                "atlasControlsNotScoredOrNotExposed": len(atlas_ss_not_scored),
                "missingControlIdsReferencedByAtlas": missing_ss_ids if "missing_ss_ids" in locals() else [],
            },
            "top10": {
                "atlasMappedGaps": top10,
                "unmappedGaps": top10_unmapped,
            },
            "tier3": {
                "blockedControls": tier3_blocked,
                "notReadySignals": tier3_not_ready,
                "summary": tier3_summary,
            },
        }

        # Console: short, customer-safe executive summary
        print("\n==== EXECUTIVE SUMMARY (Customer-safe) ====\n")
        print(f"- ATLAS controls evaluated: {len(matched)}")
        if "missing_ss_ids" in locals() and missing_ss_ids:
            print(f"- Secure Score items referenced by ATLAS but not exposed in this tenant: {len(missing_ss_ids)} (may be licensing/not applicable)")

        print(f"- Secure Score (ATLAS controls): {len(atlas_ss_below100)} gaps (<100%), {len(atlas_ss_at100)} fully implemented (100%), {len(atlas_ss_not_scored)} not scored / not exposed")
        coverage = 0.0
        if atlas_ss_controls:
            coverage = round((len(atlas_ss_scored) / len(atlas_ss_controls)) * 100.0, 1)
        print(f"- Secure Score coverage (ATLAS-mapped controls with scorePct available): {coverage}%")

        print(f"- Top gaps (ATLAS-mapped): {len(top10)} shown")
        print(f"- Top gaps (unmapped to ATLAS): {len(top10_unmapped)} shown")
        # ---- Top 3 priorities (customer-safe) ----
        priorities = []

        # 1) Business gating: Tier 3 blocked due to acknowledgements
        if tier3_blocked:
            priorities.append({
                "type": "BUSINESS_APPROVAL",
                "title": "Complete Tier 3 onboarding acknowledgements (lockout-risk controls)",
                "why": "Prevents ATLAS from enforcing high-impact controls safely until business impact is acknowledged.",
                "controls": [t.get("controlId") for t in tier3_blocked if t.get("controlId")],
                "blastRadius": "BUSINESS / APPROVAL",
            })

        # 2) Technical readiness: break-glass + phishing-resistant methods readiness
        if tier3_not_ready:
            priorities.append({
                "type": "TECHNICAL_READINESS",
                "title": "Fix Tier 3 technical readiness (break-glass + phishing-resistant MFA readiness)",
                "why": "Reduces lockout risk and enables safe enforcement of Tier 3 Conditional Access controls.",
                "controls": [t.get("controlId") for t in tier3_not_ready if t.get("controlId")],
                "blastRadius": "TECHNICAL / PREREQUISITE",
            })

        # 3) Highest-impact Secure Score gaps (use the mapped Top 10 already computed)
        # Pick the first 3 from top10 (already sorted lowest compliance first)
        if top10:
            priorities.append({
                "type": "CONFIGURATION_GAPS",
                "title": "Address highest-impact Secure Score configuration gaps (ATLAS-mapped)",
                "why": "These are the largest currently-detected gaps and typically yield fast risk reduction.",
                "items": [
                    {
                        "secureScoreControlId": x.get("controlId"),
                        "title": x.get("title"),
                        "scorePct": x.get("scorePct"),
                        "category": x.get("category"),
                        "atlasControls": ss_to_registry.get(((x.get("controlId") or "").strip().lower()), []),
                        "blastRadius": "CONFIG / QUICK WIN",
                    }
                    for x in top10[:3]
                ],

            })

        # Keep it to 3
        priorities = priorities[:3]

        # Print Top 3 priorities
        print("\n---- TOP 3 PRIORITIES ----\n")
        if not priorities:
            print("  (none)")
        else:
            for i, p in enumerate(priorities, start=1):
                label = p.get("blastRadius") or "PRIORITY"
                print(f"{i}) [{label}] {p.get('title')}")

                print(f"   why: {p.get('why')}")
                if p.get("controls"):
                    print(f"   controls: {', '.join([c for c in p['controls'] if c])}")
                if p.get("items"):
                    for it in p["items"]:
                        atlas_controls = it.get("atlasControls") or []
                        atlas_suffix = f" | atlas={', '.join(atlas_controls)}" if atlas_controls else ""
                        print(f"   - {it.get('secureScoreControlId')} | {it.get('scorePct')} | {it.get('title')}{atlas_suffix}")

                print("")

        # Add priorities into the executive summary JSON
        executive_summary["priorities"] = priorities

        # Avoid duplicating Tier 3 items if already included in Top 3 priorities
        has_business_priority = any(p.get("type") == "BUSINESS_APPROVAL" for p in priorities)
        has_readiness_priority = any(p.get("type") == "TECHNICAL_READINESS" for p in priorities)

        if tier3_blocked and not has_business_priority:
            ids = ", ".join([t.get("controlId", "") for t in tier3_blocked if t.get("controlId")])
            print(f"- Tier 3 enforcement blocked (business acknowledgements missing): {len(tier3_blocked)} [{ids}]")

        if tier3_not_ready and not has_readiness_priority:
            ids = ", ".join([t.get("controlId", "") for t in tier3_not_ready if t.get("controlId")])
            print(f"- Tier 3 technical readiness NOT READY: {len(tier3_not_ready)} [{ids}]")


        # Write executive summary JSON
        try:
            exec_out_path = os.path.join(out_dir, f"{stamp}_executive_summary.json")
            with open(exec_out_path, "w", encoding="utf-8") as f:
                json.dump(executive_summary, f, indent=2)
            print(f"\nExecutive summary JSON saved to: {exec_out_path}")
        except Exception as e:
            print(f"\nWARNING: Failed to write executive summary JSON: {e}")
            # =========================
        # Capability Matrix (v1)
        # =========================
        try:
            capability_rows = []

            # Helpful lookups
            missing_ss_ids_set = set(missing_ss_ids) if "missing_ss_ids" in locals() and missing_ss_ids else set()

            for c in registry_controls:
                cid = c.get("id")
                if not cid:
                    continue

                ss_ids = [((x or "").strip().lower()) for x in (c.get("secureScoreControlIds") or []) if (x or "").strip()]
                has_ss_mapping = bool(ss_ids)
                is_gap_only = bool(c.get("gapOnly", False))
                is_detect_only = bool(c.get("detectOnly") is True)
                has_handler = bool(c.get("handler"))  # future-ready; may be absent today

                # Determine if any mapped Secure Score IDs are missing from tenant snapshot
                ss_ids_missing_in_tenant = [x for x in ss_ids if x in missing_ss_ids_set]

                # Capability classification
                capability = None
                reason = None

                if is_gap_only:
                    capability = "GAP_ONLY"
                    reason = "Registry marked gapOnly=true (informational/backlog marker)"
                elif cid in CAPABILITY_ENFORCERS:
                    capability = "ENFORCER_IMPLEMENTED"
                    reason = "Bespoke enforcement path exists in main.py"
                elif cid in CAPABILITY_CUSTOM_DETECTORS:
                    capability = "CUSTOM_DETECTOR_IMPLEMENTED"
                    reason = "Bespoke detector path exists in main.py"
                elif has_handler:
                    # handler field exists but not necessarily wired to a dispatcher yet
                    capability = "HANDLER_DECLARED_NOT_DISPATCHED"
                    reason = "Registry has handler field, but main.py does not dispatch handlers generically yet"
                elif is_detect_only and has_ss_mapping:
                    capability = "SECURE_SCORE_ONLY"
                    reason = "detectOnly=true and posture is derived from Secure Score overlay"
                elif is_detect_only and (not has_ss_mapping):
                    capability = "CUSTOM_DETECTOR_EXPECTED"
                    reason = "detectOnly=true but no Secure Score mapping; likely needs a bespoke detector"
                else:
                    capability = "NO_HANDLER_IMPLEMENTED"
                    reason = "enforceable control but no bespoke enforcement path or handler declared"

                capability_rows.append({
                    "id": cid,
                    "name": c.get("name", cid),
                    "category": c.get("category"),
                    "tier": c.get("tier"),
                    "detectOnly": is_detect_only,
                    "gapOnly": is_gap_only,
                    "approvalRequired": bool(c.get("approvalRequired", False)),
                    "default_mode": c.get("default_mode"),
                    "secureScoreControlIds": ss_ids,
                    "secureScoreIdsMissingInTenantSnapshot": ss_ids_missing_in_tenant,
                    "capability": capability,
                    "capabilityReason": reason,
                })

            # Summary counts
            counts = {}
            for r in capability_rows:
                counts[r["capability"]] = counts.get(r["capability"], 0) + 1

            # Write to disk
            cap_path = os.path.join(out_dir, f"{stamp}_capability_matrix.json")
            with open(cap_path, "w", encoding="utf-8") as f:
                json.dump({
                    "tenant": tenant_name,
                    "generatedAt": stamp,
                    "counts": counts,
                    "rows": sorted(capability_rows, key=lambda x: (x["capability"], x.get("tier") or 0, x["id"])),
                }, f, indent=2)

            # Console summary (customer-safe, but technical)
            print("\n==== CAPABILITY MATRIX (Implementation coverage) ====\n")
            for k in sorted(counts.keys()):
                print(f"- {k}: {counts[k]}")
            print(f"\nCapability matrix JSON saved to: {cap_path}")

        except Exception as e:
            print(f"\n[WARN] Failed to write capability matrix: {e}")

        print("\n==== TIER 3 ONBOARDING SUMMARY (Business / lockout risk) ====\n")
        for t in tier3_summary:
            tags = []
            if t.get("canCauseLockout"):
                tags.append("canCauseLockout")
            if t.get("requiresOnboardingDiscussion"):
                tags.append("onboardingRequired")

            # Print in a multi-line format to avoid console wrapping
            print(f'- {t["controlId"]} | mode={t["mode"]}')
            print(f'  {t["name"]}')
            if tags:
                print(f'  tags: {", ".join(tags)}')

            if t.get("outcome") == "BLOCKED":
                print(f'  BLOCKED: {t.get("reason")}')
                if t.get("missing"):
                    print(f'  missing: {", ".join(t["missing"])}')
            elif t.get("outcome") in ("ERROR", "DRIFTED", "COMPLIANT", "NOT_EVALUATED"):
                print(f'  outcome: {t.get("outcome")}')
                if t.get("reason"):
                    print(f'  note: {t.get("reason")}')
                    if t.get("methodsSummary"):
                        print(f'  methods: {t.get("methodsSummary")}')

                    # Only show the "next" hint for the auth-methods readiness control
                    if t.get("controlId") == "Tier3AuthMethodsReadiness" and t.get("outcome") == "DRIFTED":
                        print("  next: Enable FIDO2 or Windows Hello for Business before enforcing phishing-resistant MFA controls (TAP is enabled).")

                    # Break-glass details should print for the break-glass readiness control (and any future ones)
                    if t.get("breakGlassSummary"):
                        print(f'  break-glass: {t.get("breakGlassSummary")}')
                    if t.get("breakGlassReason"):
                        print(f'  detail: {t.get("breakGlassReason")}')


            print("")  # blank line between Tier 3 items


        print("\nTier 3 controls are detect-only by default and must never be enforced without explicit customer onboarding and full acknowledgement flags in the approval file.")
        # Also write Tier 3 onboarding summary to a JSON file for reporting / onboarding packs
        try:
            tier3_out_path = os.path.join(out_dir, f"{stamp}_tier3_onboarding_summary.json")
            with open(tier3_out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "tenant": tenant_name,
                    "generatedAt": stamp,
                    "tier3Summary": tier3_summary
                }, f, indent=2)
            print(f"\nTier 3 onboarding summary JSON saved to: {tier3_out_path}")
        except Exception as e:
            print(f"\nWARNING: Failed to write Tier 3 onboarding summary JSON: {e}")

    print(f"\nSaved to: {out_dir}")

if __name__ == "__main__":
    main()