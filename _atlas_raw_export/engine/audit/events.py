import os, json
from datetime import datetime, timezone
from engine.constants import ACTION_TO_STATE, ControlState

def write_audit_event(tenant_name: str, event: dict):
    action = event.get("action")
    event.setdefault(
        "state",
        ACTION_TO_STATE.get(action, ControlState.ERROR)
    )
    # Standardised "why" block (authoritative):
    #  - Always ensure top-level reasonCode/reasonDetail exist
    #  - Always ensure event["details"] is a dict
    #  - Force details.reasonCode/details.reasonDetail to match top-level
    if "details" not in event or not isinstance(event.get("details"), dict):
        event["details"] = {} if event.get("details") is None else {"value": event.get("details")}

    # Default top-level reason fields if missing (based on state)
    if not event.get("reasonCode") or not event.get("reasonDetail"):
        st = str(event.get("state") or "").upper()
        if st == "COMPLIANT":
            event["reasonCode"] = event.get("reasonCode") or "COMPLIANT"
            event["reasonDetail"] = event.get("reasonDetail") or "Control evaluated as compliant."
        elif st == "DRIFTED":
            event["reasonCode"] = event.get("reasonCode") or "DRIFTED"
            event["reasonDetail"] = event.get("reasonDetail") or "Control evaluated as non-compliant (drift detected)."
        elif st == "AWAITING_APPROVAL":
            event["reasonCode"] = event.get("reasonCode") or "AWAITING_APPROVAL"
            event["reasonDetail"] = event.get("reasonDetail") or "Control requires approval before enforcement."
        elif st == "NOT_EVALUATED":
            event["reasonCode"] = event.get("reasonCode") or "NOT_EVALUATED"
            event["reasonDetail"] = event.get("reasonDetail") or "Control not evaluated (blocked, missing data, or error)."
        else:
            event["reasonCode"] = event.get("reasonCode") or "NOT_EVALUATED"
            event["reasonDetail"] = event.get("reasonDetail") or f"Control state={st or 'UNKNOWN'}."

    # Force details to mirror top-level (prevents mismatches)
    event["details"]["reasonCode"] = event.get("reasonCode")
    event["details"]["reasonDetail"] = event.get("reasonDetail")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join("output", "audit", tenant_name, f"{stamp}_{event['controlId']}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(event, f, indent=2)
    return path

    
