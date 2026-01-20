# engine/audit/hardening.py

def harden_audit_event_inplace(audit: dict):
    """
    Best-effort hardening to ensure every audit event has:
      - details as a dict
      - state always present
      - reasonCode / reasonDetail always present
      - details.reasonCode / details.reasonDetail mirror top-level

    IMPORTANT: This function must be behavior-identical to the hardening
    block previously embedded in engine/main.py (_write_audit_event_timed).
    """

    # Normalize details
    if "details" not in audit or audit["details"] is None:
        audit["details"] = {}
    elif not isinstance(audit["details"], dict):
        audit["details"] = {"value": audit["details"]}

    # Ensure state
    if not audit.get("state"):
        audit["state"] = "NOT_EVALUATED"

    # Prefer explicit reason fields, then details-carried reason fields, then safe defaults
    if not audit.get("reasonCode"):
        audit["reasonCode"] = audit["details"].get("reasonCode")

    if not audit.get("reasonDetail"):
        audit["reasonDetail"] = audit["details"].get("reasonDetail")

    if not audit.get("reasonCode"):
        mode = (audit.get("mode") or "").lower()
        action = audit.get("action") or ""
        status = int(audit.get("status") or 0)

        if mode == "report-only":
            audit["reasonCode"] = "REPORT_ONLY_EVALUATED"
            audit["reasonDetail"] = audit.get("reasonDetail") or "Report-only evaluation completed."

        elif mode == "detect-only":
            cid = audit.get("controlId") or ""
            if cid.startswith("Tier3"):
                audit["reasonCode"] = "TIER3_EVALUATED"
                audit["reasonDetail"] = audit.get("reasonDetail") or "Tier3 (additive) evaluation completed."
            else:
                audit["reasonCode"] = "DETECT_ONLY_EVALUATED"
                audit["reasonDetail"] = audit.get("reasonDetail") or "Detect-only evaluation completed."

        elif mode == "enforce" and action.startswith("ensure_") and status < 400:
            audit["reasonCode"] = "ENFORCER_EXECUTED"
            audit["reasonDetail"] = audit.get("reasonDetail") or "Enforcement executed successfully."

        else:
            audit["reasonCode"] = "EVALUATED"
            audit["reasonDetail"] = audit.get("reasonDetail") or "Control evaluated (no explicit reason provided)."

    # Ensure details mirrors reason fields for evidence consistency
    audit["details"].setdefault("reasonCode", audit["reasonCode"])
    audit["details"].setdefault("reasonDetail", audit["reasonDetail"])
