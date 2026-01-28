# engine/enforcement/spo_bulk_tenant_settings_enforcer.py
from __future__ import annotations
from engine.detectors.spo import set_spo_browser_idle_signout

import time
from typing import Dict, Tuple

from engine.approvals.reader import is_control_approved
from engine.enforcement.registry import register


# In-run cache to ensure: single SPO connect, single Set-SPOTenant, single verify loop.
# Keyed by tenant_name. Safe because a single engine run processes one tenant at a time.
_SPO_TENANT_SETTINGS_BATCH_CACHE: Dict[str, dict] = {}


def _parse_list(value: str | None) -> list[str]:
    if value is None:
        return []
    s = str(value).strip()
    if not s:
        return []
    # Accept commas, semicolons, newlines, or whitespace as separators
    s = s.replace(";", " ").replace(",", " ").replace("\n", " ")
    parts = [p.strip() for p in s.split() if p.strip()]
    return parts



def _desired_for_control(tenant: dict, control_id: str) -> tuple[dict, list[str]]:
    """Return (desired_settings, missing_keys).

    This is intentionally conservative:
      - Only fixed, safe defaults where the control definition is "enabled"/"restricted".
      - Any value that needs a tenant-specific choice requires explicit tenant config.
    """

    desired: dict = {}
    missing: list[str] = []

    if control_id == "SharePointPreventExternalUsersFromResharingEnabled":
        desired["PreventExternalUsersFromResharing"] = True

    elif control_id == "SharePointDefaultLinkTypeRestricted":
        # DefaultSharingLinkType: None=0, Direct=1, Internal=2, AnonymousAccess=3
        # Conservative desired: Internal (2). Allow override via tenant config.
        v = ((tenant or {}).get("spoTenantDefaults") or {}).get("DefaultSharingLinkType")
        if v is None:
            v = 2
        desired["DefaultSharingLinkType"] = int(v)

    elif control_id == "SharePointDefaultSharingRestricted":
        # DefaultLinkPermission: None=0, View=1, Edit=2
        v = ((tenant or {}).get("spoTenantDefaults") or {}).get("DefaultLinkPermission")
        if v is None:
            v = 1
        desired["DefaultLinkPermission"] = int(v)

    elif control_id == "SharePointLinkExpirationConfigured":
        # RequireAnonymousLinksExpireInDays: must be > 0 to be "configured".
        v = ((tenant or {}).get("spoTenantDefaults") or {}).get("RequireAnonymousLinksExpireInDays")
        if v is None:
            # Conservative, explainable default.
            v = 30
        desired["RequireAnonymousLinksExpireInDays"] = int(v)

    elif control_id == "SharePointIdleSessionTimeout":
        # UNSUPPORTED in this enforcement surface: Set-SPOTenant does not accept IdleSessionSignOut* parameters
        # in the SPO Management Shell being used. Do not contribute any desired keys to the bulk apply.
        missing.append("UNSUPPORTED: Set-SPOTenant does not support IdleSessionSignOut* parameters")




    elif control_id in {
        "SharePointDomainRestrictionConfigured",
        "SharePointSharingAllowedDomainListConfigured",
        "SharePointSharingBlockedDomainListConfigured",
    }:
        cfg = (tenant or {}).get("spoDomainRestriction") or {}
        mode = cfg.get("SharingDomainRestrictionMode")
        allowed = cfg.get("SharingAllowedDomainList")
        blocked = cfg.get("SharingBlockedDomainList")

        if mode is None:
            missing.append("tenant.spoDomainRestriction.SharingDomainRestrictionMode")
        else:
            mode_norm = str(mode).strip()
            if mode_norm not in ("AllowList", "BlockList"):
                missing.append("tenant.spoDomainRestriction.SharingDomainRestrictionMode (AllowList|BlockList)")
            else:
                desired["SharingDomainRestrictionMode"] = mode_norm

        if control_id == "SharePointSharingAllowedDomainListConfigured":
            if allowed is None:
                missing.append("tenant.spoDomainRestriction.SharingAllowedDomainList")
            else:
                desired["SharingAllowedDomainList"] = " ".join(_parse_list(str(allowed)))

        if control_id == "SharePointSharingBlockedDomainListConfigured":
            if blocked is None:
                missing.append("tenant.spoDomainRestriction.SharingBlockedDomainList")
            else:
                desired["SharingBlockedDomainList"] = " ".join(_parse_list(str(blocked)))

    return desired, missing


def _keys_for_control(control_id: str) -> list[str]:
    if control_id == "SharePointPreventExternalUsersFromResharingEnabled":
        return ["PreventExternalUsersFromResharing"]
    if control_id == "SharePointDefaultLinkTypeRestricted":
        return ["DefaultSharingLinkType"]
    if control_id == "SharePointDefaultSharingRestricted":
        return ["DefaultLinkPermission"]
    if control_id == "SharePointLinkExpirationConfigured":
        return ["RequireAnonymousLinksExpireInDays"]
    if control_id == "SharePointIdleSessionTimeout":
        return []
    if control_id == "SharePointDomainRestrictionConfigured":
        return ["SharingDomainRestrictionMode"]
    if control_id == "SharePointSharingAllowedDomainListConfigured":
        return ["SharingDomainRestrictionMode", "SharingAllowedDomainList"]
    if control_id == "SharePointSharingBlockedDomainListConfigured":
        return ["SharingDomainRestrictionMode", "SharingBlockedDomainList"]
    return []


def _subset(d: dict | None, keys: list[str]) -> dict:
    d = d or {}
    return {k: d.get(k) for k in keys}


def _spo_get_tenant_settings(admin_url: str) -> dict:
    from engine.detectors.spo import run_spo_tenant_settings
    return run_spo_tenant_settings(admin_url)




def _spo_set_tenant_settings_bulk(admin_url: str, desired: dict) -> dict:
    from engine.detectors.spo import set_spo_tenant_settings_bulk
    return set_spo_tenant_settings_bulk(admin_url, desired)


def _compute_state_for_control(control_id: str, tenant_settings: dict) -> tuple[str, dict]:
    """Evaluate COMPLIANT/DRIFTED conservatively from an SPO tenant settings snapshot."""
    t = (tenant_settings or {}).get("tenant") or {}
    def _mode_label(mode_val) -> str:
        if mode_val is None:
            return ""
        if isinstance(mode_val, int):
            return {0: "None", 1: "AllowList", 2: "BlockList"}.get(mode_val, str(mode_val))
        s = str(mode_val).strip()
        if s.isdigit():
            return {0: "None", 1: "AllowList", 2: "BlockList"}.get(int(s), s)
        return s
    keys = _keys_for_control(control_id)
    details = _subset(t, keys)

    if control_id == "SharePointPreventExternalUsersFromResharingEnabled":
        v = t.get("PreventExternalUsersFromResharing")
        if v is None:
            return "NOT_EVALUATED", {**details, "missingKeys": ["PreventExternalUsersFromResharing"]}
        v_norm = v if isinstance(v, bool) else str(v).strip().lower() in ("true", "1", "yes")
        return ("COMPLIANT" if v_norm else "DRIFTED"), {**details, "PreventExternalUsersFromResharing_normalized": v_norm}

    if control_id == "SharePointLinkExpirationConfigured":
        days = t.get("RequireAnonymousLinksExpireInDays")
        if days is None:
            return "NOT_EVALUATED", {**details, "missingKeys": ["RequireAnonymousLinksExpireInDays"]}
        return ("COMPLIANT" if isinstance(days, int) and days > 0 else "DRIFTED"), details

    if control_id == "SharePointDefaultLinkTypeRestricted":
        lt = t.get("DefaultSharingLinkType")
        if lt is None:
            return "NOT_EVALUATED", {**details, "missingKeys": ["DefaultSharingLinkType"]}
        if isinstance(lt, int):
            return ("COMPLIANT" if lt in (1, 2) else "DRIFTED"), details
        return ("COMPLIANT" if str(lt).strip().lower() in ("direct", "internal") else "DRIFTED"), details

    if control_id == "SharePointDefaultSharingRestricted":
        perm = t.get("DefaultLinkPermission")
        if perm is None:
            return "NOT_EVALUATED", {**details, "missingKeys": ["DefaultLinkPermission"]}
        if isinstance(perm, int):
            return ("COMPLIANT" if perm == 1 else "DRIFTED"), details
        return ("COMPLIANT" if str(perm).strip().lower() == "view" else "DRIFTED"), details

    if control_id == "SharePointIdleSessionTimeout":
        cfg = (tenant or {}).get("spoIdleSessionSignOut") or {}
        enabled = bool(cfg.get("enabled", True))
        warn_after = int(cfg.get("warnAfterSeconds", 840))       # 14 minutes default
        signout_after = int(cfg.get("signOutAfterSeconds", 900)) # 15 minutes default

        r = set_spo_browser_idle_signout(
            admin_url=_spo_admin_url_from_tenant(tenant),
            enabled=enabled,
            warn_after_seconds=warn_after,
            signout_after_seconds=signout_after,
        )
        details["idleSessionApply"] = r

        if not r.get("ok"):
            return "ERROR", "SPO_IDLE_SIGNOUT_SET_FAILED", r.get("error") or "Failed to set idle sign-out", details, "ENFORCER_EXECUTED"

        return "COMPLIANT", "ENFORCER_EXECUTED", "Idle session sign-out configured via Set-SPOBrowserIdleSignOut", details, "ENFORCER_EXECUTED"



    if control_id == "SharePointDomainRestrictionConfigured":
        mode = t.get("SharingDomainRestrictionMode")
        if mode is None:
            return "NOT_EVALUATED", {**details, "missingKeys": ["SharingDomainRestrictionMode"]}
        mode_norm = str(mode).strip()
        return ("COMPLIANT" if mode_norm.lower() not in ("none", "", "0") else "DRIFTED"), {**details, "SharingDomainRestrictionMode_normalized": mode_norm}

    if control_id == "SharePointSharingAllowedDomainListConfigured":
        mode = t.get("SharingDomainRestrictionMode")
        allowed_raw = t.get("SharingAllowedDomainList")
        missing = []
        if mode is None:
            missing.append("SharingDomainRestrictionMode")
        if allowed_raw is None:
            missing.append("SharingAllowedDomainList")
        if missing:
            return "NOT_EVALUATED", {**details, "missingKeys": missing}
        mode_norm = _mode_label(mode)
        allowed = _parse_list(str(allowed_raw))
        if mode_norm.lower() != "allowlist":
            return "DRIFTED", {**details, "SharingDomainRestrictionMode_normalized": mode_norm, "SharingAllowedDomainList_normalized": allowed, "note": "Domain restriction mode is not AllowList"}
        return ("COMPLIANT" if len(allowed) > 0 else "DRIFTED"), {**details, "SharingDomainRestrictionMode_normalized": mode_norm, "SharingAllowedDomainList_normalized": allowed}

    if control_id == "SharePointSharingBlockedDomainListConfigured":
        mode = t.get("SharingDomainRestrictionMode")
        blocked_raw = t.get("SharingBlockedDomainList")
        missing = []
        if mode is None:
            missing.append("SharingDomainRestrictionMode")
        if blocked_raw is None:
            missing.append("SharingBlockedDomainList")
        if missing:
            return "NOT_EVALUATED", {**details, "missingKeys": missing}
        mode_norm = _mode_label(mode)
        blocked = _parse_list(str(blocked_raw))
        if mode_norm.lower() != "blocklist":
            return "DRIFTED", {**details, "SharingDomainRestrictionMode_normalized": mode_norm, "SharingBlockedDomainList_normalized": blocked, "note": "Domain restriction mode is not BlockList"}
        return ("COMPLIANT" if len(blocked) > 0 else "DRIFTED"), {**details, "SharingDomainRestrictionMode_normalized": mode_norm, "SharingBlockedDomainList_normalized": blocked}

    return "NOT_EVALUATED", {"error": "Unsupported SPO tenant-settings control"}


def _run_spo_tenant_settings_batch(*, tenant: dict, tenant_name: str) -> dict:
    admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
    admin_url = (admin_url or "").strip()

    batch = {
        "adminUrl": admin_url,
        "ok": False,
        "before": None,
        "after": None,
        "desired": {},
        "applyResult": None,
        "verifyAttempts": [],
        "perControl": {},
        "error": None,
    }

    if not admin_url:
        batch["error"] = "spoAdminUrl is required"
        return batch

    # Determine which SPO tenant-settings controls are approved for enforce, and build a single desired dict.
    spo_controls = [
        "SharePointPreventExternalUsersFromResharingEnabled",
        "SharePointIdleSessionTimeout",
        "SharePointDefaultLinkTypeRestricted",
        "SharePointDefaultSharingRestricted",
        "SharePointLinkExpirationConfigured",
        "SharePointDomainRestrictionConfigured",
        "SharePointSharingAllowedDomainListConfigured",
        "SharePointSharingBlockedDomainListConfigured",
    ]

    desired_all: dict = {}
    per_control_desired: dict = {}
    per_control_missing: dict = {}

    for cid in spo_controls:
        approved, _reason, approval = is_control_approved(tenant_name, cid)
        if not approved:
            continue
        mode_eff = (approval or {}).get("mode")
        if str(mode_eff).strip().lower() != "enforce":
            continue
        desired, missing = _desired_for_control(tenant, cid)
        if missing:
            per_control_missing[cid] = missing
            continue
        if desired:
            per_control_desired[cid] = desired
            desired_all.update(desired)

    batch["desired"] = desired_all
    batch["desiredByControl"] = per_control_desired
    if per_control_missing:
        batch["missingDesiredConfigByControl"] = per_control_missing

    # Read current
    pre = _spo_get_tenant_settings(admin_url)
    batch["before"] = pre
    if not (pre or {}).get("ok"):
        batch["error"] = f"SPO read failed: {(pre or {}).get('error')}"
        return batch

    # If nothing approved for enforce, we're done (evaluation-only batch).
    if not desired_all:
        batch["ok"] = True
        batch["after"] = pre
        return batch

    # Apply once
    apply_res = _spo_set_tenant_settings_bulk(admin_url, desired_all)
    batch["applyResult"] = apply_res
    if isinstance(apply_res, dict) and apply_res.get("ok") is False:
        batch["error"] = f"SPO bulk apply failed: {apply_res.get('error')}"
        return batch

    # Verify with retries (propagation-aware)
    desired_keys = list(desired_all.keys())

    def _equiv(k: str, actual, desired) -> bool:
        # SharePoint returns SharingDomainRestrictionMode as int enum (0/1/2) but we may set strings.
        if k == "SharingDomainRestrictionMode":
            want = str(desired).strip().lower()
            if want.isdigit():
                want_n = int(want)
            else:
                want_n = {"none": 0, "allowlist": 1, "blocklist": 2}.get(want, None)

            act = actual
            if isinstance(act, str) and act.strip().isdigit():
                act = int(act.strip())

            if isinstance(act, int) and want_n is not None:
                return act == want_n
            # Fallback string compare
            return str(actual).strip().lower() == str(desired).strip().lower()

        return actual == desired

    best_post = None
    best_mismatches = 10**9

    for attempt in range(1, 6):
        time.sleep(3.0)
        post = _spo_get_tenant_settings(admin_url)
        batch["verifyAttempts"].append(post)
        if not (post or {}).get("ok"):
            continue

        t = (post or {}).get("tenant") or {}

        mismatches = 0
        for k in desired_keys:
            if not _equiv(k, t.get(k), desired_all.get(k)):
                mismatches += 1

        if mismatches < best_mismatches:
            best_mismatches = mismatches
            best_post = post

        if mismatches == 0:
            batch["ok"] = True
            batch["after"] = post
            return batch

    # Not converged: keep the best snapshot we saw (prevents a late transient read from poisoning "after")
    batch["ok"] = True
    batch["after"] = best_post if best_post is not None else pre
    return batch


    # Not converged
    batch["ok"] = True
    batch["after"] = (batch["verifyAttempts"][-1] if batch["verifyAttempts"] else pre)
    return batch


def _spo_batch_enforcer(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:

    mode_eff = (mode or "report-only").strip().lower()
    default_mode = (control or {}).get("default_mode") or ""
    default_mode = str(default_mode).strip().lower()

    rc_eval = "DETECT_ONLY_EVALUATED" if default_mode == "detect-only" else "REPORT_ONLY_EVALUATED"
    rc_enf = "ENFORCER_EXECUTED"

    # Ensure batch cache exists
    if tenant_name not in _SPO_TENANT_SETTINGS_BATCH_CACHE:
        _SPO_TENANT_SETTINGS_BATCH_CACHE[tenant_name] = _run_spo_tenant_settings_batch(tenant=tenant, tenant_name=tenant_name)

    batch = _SPO_TENANT_SETTINGS_BATCH_CACHE.get(tenant_name) or {}
    admin_url = batch.get("adminUrl")

    if not admin_url:
        return ("NOT_EVALUATED", "MISSING_SIGNAL", "spoAdminUrl not set in tenant config", {"missingKeys": ["spoAdminUrl"]}, 424)

    if batch.get("error"):
        return ("NOT_EVALUATED", "MISSING_SIGNAL", str(batch.get("error")), {"batch": batch}, 424)
    if control_id == "SharePointIdleSessionTimeout" and mode_eff == "enforce":
        details = {
            "adminUrl": admin_url,
            "note": "UNSUPPORTED: Set-SPOTenant does not support IdleSessionSignOut* parameters in this environment",
        }
        return ("NOT_EVALUATED", "UNSUPPORTED_MODE", "Cannot enforce SharePoint idle session via SPO Management Shell (Set-SPOTenant)", details, 424)

    # Evaluate state from the best available snapshot.
    snap = batch.get("after") if (mode_eff == "enforce") else batch.get("before")
    state, eval_details = _compute_state_for_control(control_id, snap or {})

    keys = _keys_for_control(control_id)
    t_before = ((batch.get("before") or {}).get("tenant") or {}) if isinstance(batch.get("before"), dict) else {}
    t_after = ((batch.get("after") or {}).get("tenant") or {}) if isinstance(batch.get("after"), dict) else {}

    # Per-control desired calculation (for evidence) - even if not approved/configured.
    desired_one, missing_cfg = _desired_for_control(tenant, control_id)

    details = {
        "adminUrl": admin_url,
        "batchDesiredAll": batch.get("desired") or {},
        "missingDesiredConfigByControl": batch.get("missingDesiredConfigByControl") or {},
        "before": {control_id: _subset(t_before, keys)},
        "desired": {control_id: _subset(desired_one, keys)},
        "after": {control_id: _subset(t_after, keys)} if mode_eff == "enforce" else {control_id: _subset(t_before, keys)},
        "evaluate": eval_details or {},
    }
    if missing_cfg:
        details.setdefault("evaluate", {})["missingDesiredConfig"] = missing_cfg

    if mode_eff != "enforce":
        # Pure evaluation
        msg = "Evaluated via SharePoint tenant settings (SPO PowerShell)"
        return (state, rc_eval if state != "ERROR" else "CUSTOM_DETECTOR_ERROR", msg, details, 200)

    # Enforce: include apply + verify evidence
    details["applyResult"] = batch.get("applyResult")
    details["verifyAttempts"] = batch.get("verifyAttempts")

    if state == "COMPLIANT":
        return ("COMPLIANT", rc_enf, "Enforcer executed; setting verified", details, 200)
    if state == "DRIFTED":
        return ("DRIFTED", rc_enf, "Enforcer executed; drift remains after verify", details, 200)
    if state == "NOT_EVALUATED":
        return ("NOT_EVALUATED", "MISSING_SIGNAL", "Could not evaluate/enforce via SPO tenant settings", details, 424)
    if state == "ERROR":
        return ("ERROR", "ENFORCER_ERROR", "SPO tenant-settings enforcement failed", details, 500)

    return ("ERROR", "ENFORCER_ERROR", "Unexpected SPO tenant-settings enforcement result", details, 500)


# Register as the enforcer for SPO tenant-settings controls (batch-based).
register("SharePointPreventExternalUsersFromResharingEnabled", _spo_batch_enforcer)
register("SharePointIdleSessionTimeout", _spo_batch_enforcer)
register("SharePointDefaultLinkTypeRestricted", _spo_batch_enforcer)
register("SharePointDefaultSharingRestricted", _spo_batch_enforcer)
register("SharePointLinkExpirationConfigured", _spo_batch_enforcer)
register("SharePointDomainRestrictionConfigured", _spo_batch_enforcer)
register("SharePointSharingAllowedDomainListConfigured", _spo_batch_enforcer)
register("SharePointSharingBlockedDomainListConfigured", _spo_batch_enforcer)
