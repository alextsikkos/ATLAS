# engine/enforcement/spo_prevent_reshare_enforcer.py
from __future__ import annotations

from typing import Tuple

from engine.enforcement.registry import register


def _spo_prevent_external_users_from_resharing(
    *,
    tenant: dict,
    tenant_name: str,
    control: dict,
    control_id: str,
    headers: dict,
    approval: dict | None,
    mode: str,
) -> Tuple[str, str, str, dict, int]:
    # Reuse the existing, proven SPO enforcement function (no new logic).
    from engine.enforcement.spo import apply_spo_prevent_external_users_from_resharing

    admin_url = (tenant or {}).get("spoAdminUrl") or (tenant or {}).get("spoAdminURL") or (tenant or {}).get("spo_admin_url")
    admin_url = (admin_url or "").strip()

    mode_eff = (mode or "report-only").strip().lower()

    state, details = apply_spo_prevent_external_users_from_resharing(
        admin_url=admin_url,
        mode=mode_eff,
    )

    # Map existing function states to registry contract.
    # (Keep conservative; never lie.)
    if state == "UPDATED":
        return ("COMPLIANT", "ENFORCER_EXECUTED", "Enforcer executed; setting updated and verified", details or {}, 200)
    if state == "COMPLIANT":
        return ("COMPLIANT", "ENFORCER_EXECUTED" if mode_eff == "enforce" else "REPORT_ONLY_EVALUATED", "Already in desired state", details or {}, 200)
    if state == "DRIFTED":
        # If we are enforcing and drift remains, we attempted enforcement but it didn't converge.
        rc = "ENFORCER_EXECUTED" if mode_eff == "enforce" else "REPORT_ONLY_EVALUATED"
        msg = "Enforcer executed; drift remains after verify" if mode_eff == "enforce" else "Report-only: drift detected"
        return ("DRIFTED", rc, msg, details or {}, 200)

    if state == "NOT_EVALUATED":
        return ("NOT_EVALUATED", "MISSING_SIGNAL", "Could not evaluate/enforce via SPO admin settings", details or {}, 424)
    # If the underlying helper returned ERROR, preserve its error context.
    if state == "ERROR":
        return ("ERROR", "ENFORCER_ERROR", "SPO enforcement failed", details or {}, 500)

    return ("ERROR", "ENFORCER_ERROR", "Unexpected SPO enforcement result", {"details": details, "rawState": state}, 500)



register("SharePointPreventExternalUsersFromResharingEnabled", _spo_prevent_external_users_from_resharing)
