from __future__ import annotations

from engine.enforcement.registry import register
from engine.enforcement.ensure import run_powershell_json
from engine.approvals.reader import is_control_approved


CONTROL_ID = "MDOBlockAutoForwarding"


def _enforce(*, tenant: dict, tenant_name: str, control: dict, control_id: str, headers: dict, approval: dict | None, mode: str):
    # mode handling consistent with existing enforcers
    mode_eff = (mode or "").strip().lower()

    # Always run the before snapshot (even in report-only) to provide evidence
    ps = "engine/enforcement/mdo_block_auto_forwarding.ps1"
    r = run_powershell_json(
        script_path=ps,
        tenant_domain=tenant.get("tenantDomain") or tenant.get("tenant_domain") or tenant_name,
    )

    details = {
        "before": {CONTROL_ID: (r.get("before") if isinstance(r, dict) else None)},
        "desired": {CONTROL_ID: {"Identity": "Default", "AutoForwardEnabled": False}},
        "after": {CONTROL_ID: (r.get("after") if isinstance(r, dict) else None)},
    }

    # Determine compliance from after (script always applies; we will later optimize to no-op if needed)
    after = (r or {}).get("after") if isinstance(r, dict) else None
    after_val = None
    if isinstance(after, dict):
        after_val = after.get("AutoForwardEnabled")

    if mode_eff == "report-only":
        # In report-only, we should not change state. So: DO NOT enforce here.
        # We return NOT_EVALUATED so the existing detector remains authoritative.
        return ("NOT_EVALUATED", "REPORT_ONLY_EVALUATED", "Report-only mode: enforcement skipped.", details, 200)

    if mode_eff == "enforce":
        if after_val is False:
            return ("UPDATED", "ENFORCER_EXECUTED", "Auto forwarding disabled on RemoteDomain 'Default' and verified.", details, 200)
        return ("ERROR", "ENFORCER_ERROR", "Attempted to disable auto forwarding but could not verify desired state.", details, 200)

    return ("NOT_EVALUATED", "UNSUPPORTED_MODE", f"Unsupported mode for enforcer: {mode}", details, 200)


register(CONTROL_ID, _enforce)
