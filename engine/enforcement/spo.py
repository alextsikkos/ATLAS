# engine/enforcement/spo.py
from __future__ import annotations

import time


def apply_spo_prevent_external_users_from_resharing(*, admin_url: str, mode: str):
    """
    Wrapper used by main.py and registry enforcers.

    Returns: (state, details)
      state in: COMPLIANT | DRIFTED | UPDATED | NOT_EVALUATED | ERROR
    """
    mode = (mode or "report-only").strip().lower()
    details = {"adminUrl": admin_url, "mode": mode}

    if not admin_url:
        details["missingKeys"] = ["spoAdminUrl"]
        return ("NOT_EVALUATED", details)

    # We intentionally depend on the existing SPO detector helpers (no new PS scripts).
    try:
        from engine.detectors import spo as spo_det
    except Exception as e:
        details["error"] = f"Failed to import engine.detectors.spo: {e}"
        return ("NOT_EVALUATED", details)

    # Read current tenant settings
    try:
        read_fn = getattr(spo_det, "run_spo_tenant_settings", None) or getattr(spo_det, "get_spo_tenant_settings", None)
        if not callable(read_fn):
            details["error"] = "No SPO tenant settings read function found (expected run_spo_tenant_settings or get_spo_tenant_settings)."
            return ("NOT_EVALUATED", details)

        pre = read_fn(admin_url)
        details["beforeRead"] = pre
        if not (pre or {}).get("ok"):
            details["error"] = f"SPO read failed: {(pre or {}).get('error')}"
            return ("NOT_EVALUATED", details)

        t = (pre or {}).get("tenant") or {}
        cur = t.get("PreventExternalUsersFromResharing")
        details["before"] = {"PreventExternalUsersFromResharing": cur}

        if cur is None:
            details["missingKeys"] = ["PreventExternalUsersFromResharing"]
            return ("NOT_EVALUATED", details)

        cur_norm = cur if isinstance(cur, bool) else str(cur).strip().lower() in ("true", "1", "yes")
        details["before_normalized"] = {"PreventExternalUsersFromResharing": cur_norm}

        # Report-only: evaluate only
        if mode != "enforce":
            return ("COMPLIANT" if cur_norm else "DRIFTED", details)

        # Enforce: idempotent
        if cur_norm is True:
            details["note"] = "Already enabled; no changes required."
            return ("COMPLIANT", details)

        # Try to find an existing setter in engine.detectors.spo
        setter = (
            getattr(spo_det, "set_spo_prevent_external_users_from_resharing", None)
            or getattr(spo_det, "set_spo_tenant_setting", None)
            or getattr(spo_det, "set_spo_tenant_settings", None)
        )
        if not callable(setter):
            details["error"] = "No SPO setter function found in engine.detectors.spo for PreventExternalUsersFromResharing."
            return ("NOT_EVALUATED", details)

        # Apply
        try:
            # Support both specialized setter and generic setters
            if setter.__name__ == "set_spo_prevent_external_users_from_resharing":
                apply_res = setter(admin_url=admin_url, enabled=True)
            elif setter.__name__ == "set_spo_tenant_setting":
                apply_res = setter(admin_url=admin_url, name="PreventExternalUsersFromResharing", value=True)
            else:
                apply_res = setter(admin_url=admin_url, **{"PreventExternalUsersFromResharing": True})

            details["applyResult"] = apply_res
            if isinstance(apply_res, dict) and apply_res.get("ok") is False:
                details["error"] = f"Apply failed: {apply_res.get('error')}"
                return ("ERROR", details)
        except Exception as e:
            details["error"] = f"Apply threw exception: {e}"
            return ("ERROR", details)

        # Verify with retries (SPO tenant settings can take time to propagate)
        aft_norm = None
        for attempt in range(1, 6):  # up to ~15s total
            time.sleep(3.0)
            post = read_fn(admin_url)
            details[f"afterRead_attempt_{attempt}"] = post

            if not (post or {}).get("ok"):
                continue

            tt = (post or {}).get("tenant") or {}
            aft = tt.get("PreventExternalUsersFromResharing")
            details["after"] = {"PreventExternalUsersFromResharing": aft}
            aft_norm = aft if isinstance(aft, bool) else str(aft).strip().lower() in ("true", "1", "yes")
            details["after_normalized"] = {"PreventExternalUsersFromResharing": aft_norm}

            if aft_norm is True:
                return ("UPDATED", details)

        # If we never saw it flip
        return ("DRIFTED", details)


    except Exception as e:
        details["error"] = f"Unhandled SPO enforcement exception: {e}"
        return ("ERROR", details)
