from engine.enforcement.ca_client import find_policy_by_name, create_policy, patch_policy

def _prune(x):
    if isinstance(x, dict):
        cleaned = {}
        for k, v in x.items():
            # ✅ drop Graph metadata
            if "@odata" in k:
                continue

            pv = _prune(v)
            if pv is None or pv == {} or pv == []:
                continue
            cleaned[k] = pv
        return cleaned
    return x  # primitives
    
def _normalize_policy(d: dict) -> dict:
    core = {
        "state": d.get("state"),
        "conditions": d.get("conditions"),
        "grantControls": d.get("grantControls"),
    }
    core = _prune(core)
    # ✅ ignore excludeUsers for drift detection (v1)
    users = core.get("conditions", {}).get("users", {})
    if isinstance(users, dict) and "excludeUsers" in users:
        users.pop("excludeUsers", None)
    return core

def ensure_policy(headers: dict, display_name: str, payload: dict, allow_update: bool = True):
    existing, debug = find_policy_by_name(headers, display_name)

    if debug and debug.get("ok") is False:
        return {
            "result": "error",
            "status": int(debug.get("status") or 504),
            "policyId": None,
            "errorBody": debug,
            "errorText": debug.get("error") or "Conditional Access policy lookup failed",
            "payload": payload,
        }

    if not existing:
        status, body, text = create_policy(headers, payload)
        policy_id = None
        if isinstance(body, dict):
            policy_id = body.get("id")
        result = {
            "result": "created",
            "status": status,
            "policyId": policy_id,
            "body": body,
        }
        # If Graph rejected the request, carry error details forward
        if status >= 400:
            result["result"] = "error"
        return result
    # ✅ drift detection
    existing_norm = _normalize_policy(existing)
    payload_norm = _normalize_policy(payload)
    if existing_norm == payload_norm:
        return {"result": "skipped_no_drift", "status": 200, "policyId": existing["id"], "body": existing}
    if not allow_update:
        return {"result": "skipped_update_disabled", "status": 200, "policyId": existing["id"], "body": existing}
    status, body, text = patch_policy(headers, existing["id"], payload)
    result = {
        "result": "updated",
        "status": status,
        "policyId": existing["id"],
        "body": body,
    }
    if status >= 400:
        result["result"] = "error"
    return result
