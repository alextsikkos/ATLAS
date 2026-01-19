import argparse
import os
from datetime import datetime
from engine.registry.loader import load_controls
from engine.reporting.report import _latest_audits, _latest_audits_by_control  # reuse existing helpers
from datetime import datetime, timezone

STATE_LABELS = {
    "ensure_skipped_no_drift": "COMPLIANT",
    "ensure_updated": "UPDATED",
    "ensure_created": "CREATED",
    "ensure_skipped_update_disabled": "BLOCKED (UPDATE DISABLED)",
    "ensure_skipped_awaiting_approval": "AWAITING_APPROVAL",
    "ensure_skipped_no_handler": "APPROVED_NOT_IMPLEMENTED",
    "COMPLIANT": "COMPLIANT",
    "UPDATED": "UPDATED",
    "CREATED": "CREATED",
    "AWAITING_APPROVAL": "AWAITING_APPROVAL",
    "APPROVED_NOT_IMPLEMENTED": "APPROVED_NOT_IMPLEMENTED",
    "DRIFTED": "DRIFTED",
    "detect_only": "DRIFTED",

}

STATE_SEVERITY = {
    "ERROR": 0,
    "AWAITING_APPROVAL": 1,
    "APPROVED_NOT_IMPLEMENTED": 2,
    "BLOCKED (UPDATE DISABLED)": 3,
    "UPDATED": 4,
    "CREATED": 5,
    "COMPLIANT": 6,
    "NOT_EVALUATED": 7,
    "UNKNOWN": 8,
}

def _fmt_time(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ""



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True, help="Tenant name key (e.g. example)")
    args = parser.parse_args()
    tenant = args.tenant

    controls = load_controls()

    # Latest audit event per control (based on your report logic)
    audits = _latest_audits(tenant)
    audits = _latest_audits_by_control(audits)

    # Build a quick lookup: controlId -> latest audit dict
    latest_by_control = {}
    for a, fn, full, mtime in audits:
        cid = a.get("controlId") or ""
        if cid:
            latest_by_control[cid] = (a, fn, mtime)

    print(f"Atlas status — {tenant}")
    print("")

    # High-level summary
    print(f"Registry controls: {len(controls)}")
    print(f"Audited controls (latest state): {len(latest_by_control)}")
    print("")

    # Table header
    print(f"{'Control':30} {'Tier':>4} {'State':25} {'Last Seen':18} {'Mode':10}")
    print("-" * 95)

    rows = []

    for c in sorted(controls, key=lambda x: x.get("id", "")):
        cid = c.get("id", "")
        tier = c.get("tier", "")
        entry = latest_by_control.get(cid)

        if not entry:
            state = "NOT_EVALUATED"
            last_seen = ""
            mode = ""
        else:
            a, fn, mtime = entry
            raw = a.get("state") or a.get("action") or a.get("result") or a.get("status") or "UNKNOWN"
            state = STATE_LABELS.get(raw, raw)
            last_seen = _fmt_time(mtime)
            mode = a.get("mode", "")

        sev = STATE_SEVERITY.get(state, STATE_SEVERITY["UNKNOWN"])
        rows.append((sev, cid, tier, state, last_seen, mode))

    # Sort by severity first, then control ID
    rows.sort(key=lambda x: (x[0], x[1]))

    from collections import Counter
    counts = Counter([r[3] for r in rows])
    print("Summary:", ", ".join([f"{k}={v}" for k,v in counts.items()]))
    print("")

    for sev, cid, tier, state, last_seen, mode in rows:
        print(f"{cid:30} {str(tier):>4} {state:25} {last_seen:18} {mode:10}")


    print("")
    print("Legend:")
    print("- NOT_EVALUATED: control exists in registry but no audit file found yet")
    print("- COMPLIANT: control matches desired state (no drift)")
    print("- UPDATED / CREATED: Atlas enforced a change")
    print("- AWAITING_APPROVAL: Tier-2 control needs approval JSON before running")
    print("- APPROVED_NOT_IMPLEMENTED: approved, but no handler exists yet")
    print("- BLOCKED (UPDATE DISABLED): would change, but updates disabled")


if __name__ == "__main__":
    main()