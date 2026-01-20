from typing import Any, Dict, Tuple


def apply_self_service_password_reset(graph, mode: str = "enforce") -> Tuple[str, Dict[str, Any]]:
    """
    Enforce (or report-only check) for SSPR tenant-level flag via:
      GET   /v1.0/policies/authenticationMethodsPolicy
      PATCH /v1.0/policies/authenticationMethodsPolicy  (enforce mode only)

    mode:
      - "report-only": never changes tenant, only reports drift
      - "enforce": applies changes when drifted

    Returns:
      ("COMPLIANT" | "DRIFTED" | "UPDATED" | "ERROR", details)
    """

    mode = (mode or "enforce").strip().lower()
    path = "/v1.0/policies/authenticationMethodsPolicy"

    try:
        current = graph.get(path)
    except Exception as e:
        return "ERROR", {
            "reason": "Failed to GET authenticationMethodsPolicy via Graph",
            "path": path,
            "error": str(e),
        }

    enabled = current.get("isSelfServicePasswordResetEnabled", None)

    # Already correct
    if enabled is True:
        return "COMPLIANT", {
            "current": {"isSelfServicePasswordResetEnabled": True},
            "mode": mode,
            "note": "SSPR already enabled.",
        }

    # If report-only: do NOT patch
    if mode == "report-only":
        return "DRIFTED", {
            "current": {"isSelfServicePasswordResetEnabled": enabled},
            "mode": mode,
            "note": "SSPR is not enabled, but this run is report-only (no changes applied).",
        }

    desired = {"isSelfServicePasswordResetEnabled": True}

    try:
        patched = graph.patch(path, json_body=desired)
    except Exception as e:
        return "ERROR", {
            "reason": "Failed to PATCH authenticationMethodsPolicy via Graph",
            "path": path,
            "desired": desired,
            "current": {"isSelfServicePasswordResetEnabled": enabled},
            "mode": mode,
            "error": str(e),
        }

    return "UPDATED", {
        "before": {"isSelfServicePasswordResetEnabled": enabled},
        "after": patched if patched is not None else {"isSelfServicePasswordResetEnabled": True},
        "mode": mode,
        "note": "SSPR enabled.",
    }
