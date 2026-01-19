import argparse
import json
import os
from datetime import datetime
from engine.registry.loader import load_controls, build_securescore_to_atlas_map

FINDINGS_ROOT = os.path.join("output", "findings")
AUDIT_ROOT = os.path.join("output", "audit")
REPORT_ROOT = os.path.join("output", "reports")

OUTCOME_LABELS = {
    # Canonical states (preferred)
    "COMPLIANT": "COMPLIANT",
    "UPDATED": "UPDATED",
    "CREATED": "CREATED",
    "AWAITING_APPROVAL": "AWAITING_APPROVAL",
    "APPROVED_NOT_IMPLEMENTED": "APPROVED_NOT_IMPLEMENTED",
    "NOT_EVALUATED": "NOT_EVALUATED",
    "ERROR": "ERROR",

    # Back-compat: map actions to canonical states
    "ensure_skipped_no_drift": "COMPLIANT",
    "ensure_updated": "UPDATED",
    "ensure_created": "CREATED",
    "ensure_skipped_awaiting_approval": "AWAITING_APPROVAL",
    "ensure_skipped_no_handler": "APPROVED_NOT_IMPLEMENTED",
    "ensure_skipped_update_disabled": "BLOCKED_UPDATE_DISABLED",
}


def _audit_time_key(fn: str, mtime: float):
    """
    Prefer parsing timestamp from filename 'YYYY-MM-DD_HH-MM-SS_*'.
    Fallback to mtime.
    """
    try:
        # e.g. 2026-01-01_23-31-48_AdminMFAV2.json
        ts = fn.split("_", 2)[:2]  # ['2026-01-01', '23-31-48']
        dt = datetime.strptime("_".join(ts), "%Y-%m-%d_%H-%M-%S")
        return dt.timestamp()
    except Exception:
        return mtime

def _scorepct(item):
    try:
        return float(item.get("scorePct", 9999))
    except Exception:
        return 9999

def _recommended_controls_from_gaps(top_gaps, evaluated_control_ids, ss_to_atlas_map):
    """
    top_gaps: list of findings items (dicts)
    evaluated_control_ids: set of Atlas control IDs already evaluated (from audit)
    Returns: list of (atlas_control_id, reason_title, scorepct)
    """
    recs = []

    for item in (top_gaps or [])[:25]:  # consider more than 10 for recs, still bounded
        if not isinstance(item, dict):
            continue

        gap_control_id = item.get("controlId", "")
        scorepct = item.get("scorePct", None)
        title = item.get("title", "")

        atlas_control = ss_to_atlas_map.get(gap_control_id)
        if not atlas_control:
            continue

        # Skip controls already fully compliant in Secure Score
        try:
            if float(scorepct) >= 100:
                continue
        except Exception:
            pass

        # Don't recommend if already evaluated/enforced by Atlas
        if atlas_control in evaluated_control_ids:
            continue

        recs.append((atlas_control, title, scorepct))

    # Sort: lowest scorepct first (biggest gap first)
    def _score_key(x):
        sp = x[2]
        try:
            return float(sp)
        except Exception:
            return 9999

    recs.sort(key=_score_key)
    return recs


def _summarise_audits(audits):
    """
    audits: list of tuples (audit_dict, fn, full, mtime) already deduped to latest per control
    Returns counts by action/result and a list of control IDs.
    """
    controls = []
    counts = {}

    for a, fn, full, mtime in audits:
        cid = a.get("controlId") or a.get("control") or ""
        if cid:
            controls.append(cid)

        # Prefer result/status if present, otherwise action
        key = a.get("state") or a.get("action") or a.get("result") or a.get("status") or "unknown"
        label = OUTCOME_LABELS.get(key, key)
        counts[label] = counts.get(label, 0) + 1


    return controls, counts

def _latest_audits_by_control(audits):
    """
    audits: list of tuples (audit_dict, fn, full, mtime)
    returns: list of tuples filtered to latest per controlId
    """
    latest = {}
    for a, fn, full, mtime in audits:
        control_id = a.get("controlId") or a.get("control") or ""
        if not control_id:
            continue
        t = _audit_time_key(fn, mtime)
        prev = latest.get(control_id)
        if not prev or t > prev[4]:
            latest[control_id] = (a, fn, full, mtime, t)

    # stable output order
    out = list(latest.values())
    out.sort(key=lambda x: x[4])
    # drop the computed key
    return [(a, fn, full, mtime) for (a, fn, full, mtime, _) in out]

def _list_dirs(path: str):
    if not os.path.isdir(path):
        return []
    return [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]


def _latest_findings_folder(tenant: str) -> str:
    tenant_path = os.path.join(FINDINGS_ROOT, tenant)
    dirs = _list_dirs(tenant_path)
    if not dirs:
        raise FileNotFoundError(f"No findings folders found for tenant '{tenant}' in {tenant_path}")

    # Your folders are timestamp-like; lexicographic sort works.
    dirs.sort()
    return os.path.join(tenant_path, dirs[-1])


def _read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _latest_audits(tenant: str):
    tenant_path = os.path.join(AUDIT_ROOT, tenant)
    if not os.path.isdir(tenant_path):
        return []

    audits = []
    for fn in os.listdir(tenant_path):
        if not fn.lower().endswith(".json"):
            continue
        full = os.path.join(tenant_path, fn)
        try:
            audits.append((_read_json(full), fn, full, os.path.getmtime(full)))
        except Exception:
            continue

    audits.sort(key=lambda x: x[3])  # by mtime
    return audits


def _md_escape(s: str) -> str:
    return str(s).replace("\n", " ").strip()


def build_report(tenant: str) -> str:
    latest_folder = _latest_findings_folder(tenant)

    findings_path = os.path.join(latest_folder, "findings.json")
    score_path = os.path.join(latest_folder, "securescore_latest.json")

    controls_registry = load_controls()
    SECURESCORE_TO_ATLAS_RECOMMENDATIONS = build_securescore_to_atlas_map(controls_registry)

    findings = _read_json(findings_path)
    score = _read_json(score_path)

    audits = _latest_audits(tenant)
    audits = _latest_audits_by_control(audits)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    score_current = score.get("currentScore")
    score_max = score.get("maxScore")

    lines = []
    lines.append(f"# Atlas Security Report — {tenant}")
    lines.append("")
    lines.append(f"Generated: **{now}**")
    lines.append("")
    lines.append("## Secure Score")
    lines.append("")
    if score_current is not None and score_max:
        pct = (float(score_current) / float(score_max)) * 100 if float(score_max) else 0
        lines.append(f"- Current score: **{score_current} / {score_max} ({pct:.1f}%)**")

    else:
        lines.append("- Secure Score values not found in securescore_latest.json")
    lines.append("")

    # --- Executive Summary ---
    controls, counts = _summarise_audits(audits)

    lines.append("## Executive Summary")
    lines.append("")

    if score_current is not None and score_max:
        pct = (float(score_current) / float(score_max)) * 100 if float(score_max) else 0
        lines.append(f"- Secure Score: **{score_current} / {score_max} ({pct:.1f}%)**")
    else:
        lines.append("- Secure Score: _not available_")

    if audits:
        lines.append(f"- Atlas controls evaluated (latest state): **{len(set(controls))}**")
        # show the top 3 states for readability
        top_states = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:3]
        states_str = ", ".join([f"`{k}`={v}" for k, v in top_states])
        lines.append(f"- Current Posture: {states_str}")
        
    else:
        lines.append("- Atlas controls evaluated: **0** (no audit files found)")

    lines.append("")


    # --- Top gaps ---
    lines.append("## Top Secure Score Gaps (<100%)")
    lines.append("")

    # Determine top gaps depending on whether findings.json is a dict or a list
    if isinstance(findings, list):
        top = findings
    elif isinstance(findings, dict):
        top = findings.get("top_gaps") or findings.get("gaps") or []
    else:
        top = []

    # Only show actual gaps (< 100%), sorted lowest-first
    top_gaps_only = [x for x in (top or []) if isinstance(x, dict) and _scorepct(x) < 100]
    top_gaps_only.sort(key=_scorepct)

    # Compute registry coverage BEFORE printing it
    covered = 0
    covered_ids = set(SECURESCORE_TO_ATLAS_RECOMMENDATIONS.keys())
    for item in top_gaps_only:
        if item.get("controlId") in covered_ids:
            covered += 1

    # Print coverage ABOVE the table (valid markdown)
    lines.append(f"_Registry coverage of gaps: **{covered} / {len(top_gaps_only)}**_")
    lines.append("")

    # Table header
    lines.append("| Score% | Category | Control ID | Title | Implementation | Action |")
    lines.append("|---:|---|---|---|---|---|")

    if not top_gaps_only:
        lines.append("_No Secure Score gaps detected (all listed controls are fully compliant)._")
        lines.append("")

    for item in top_gaps_only[:10]:
        if not isinstance(item, dict):
            continue

        scorepct = item.get("scorePct", "")
        cat = item.get("category", "")
        cid = item.get("controlId", "")
        title = item.get("title", "")

        impl = item.get("implementationStatus", "")
        url = item.get("actionUrl", "")

        action_link = f"[Open]({_md_escape(url)})" if url else ""

        lines.append(
            f"| {scorepct} | {_md_escape(cat)} | `{_md_escape(cid)}` | "
            f"{_md_escape(title)} | {_md_escape(impl)} | {action_link} |"
        )


    lines.append("")
    # --- Recommended Next Atlas Controls ---
    lines.append("## Recommended Next Atlas Controls")
    lines.append("")

    evaluated = set(controls)  # from _summarise_audits

    # Reuse the same 'top' list you already built for the gaps table
    recs = _recommended_controls_from_gaps(top_gaps_only, evaluated, SECURESCORE_TO_ATLAS_RECOMMENDATIONS)

    if not recs:
        lines.append("_No recommendations available (either no mapping exists yet, or recommended controls are already evaluated)._")
        lines.append("")
    else:
        lines.append("Based on Microsoft Secure Score gaps, Atlas recommends implementing the following controls next:")
        lines.append("")
        for atlas_control, reason_title, scorepct in recs[:8]:
            sp = "" if scorepct is None else f" (gap score: {scorepct}%)"
            lines.append(f"- **{atlas_control}**{sp} — { _md_escape(reason_title) }")
        lines.append("")

    # --- Enforcement summary ---
    lines.append("## Atlas Enforcement (latest audit events)")
    lines.append("")
    if not audits:
        lines.append("_No audit files found._")
        lines.append("")
    else:
        lines.append("| Time (file) | Control ID | State | Action | Result | Policy ID | Mode |")
        lines.append("|---|---|---|---|---|---|---|")


        # show the most recent 20
        for a, fn, full, mtime in audits[-20:]:
            control_id = a.get("controlId", "")
            state = a.get("state", "")
            action = a.get("action", "")
            mode = a.get("mode", "")
            policy_id = a.get("policyId", a.get("existingPolicyId", ""))

            result = "" if action == "detect_only" else a.get("result", a.get("status", action))

            lines.append(
                f"| `{fn}` | `{_md_escape(control_id)}` | "
                f"`{_md_escape(state)}` | {_md_escape(action)} | {_md_escape(result)} | "
                f"`{_md_escape(policy_id)}` | `{_md_escape(mode)}` |"
            )


    lines.append("")
    lines.append("> Tip: Audit filenames include timestamps; newest entries are at the bottom of the table.")
    lines.append("")

    # --- Files referenced ---
    lines.append("## Evidence")
    lines.append("")
    lines.append(f"- Findings folder: `{latest_folder}`")
    lines.append(f"- Findings JSON: `{findings_path}`")
    lines.append(f"- Secure Score JSON: `{score_path}`")
    lines.append(f"- Audit folder: `{os.path.join(AUDIT_ROOT, tenant)}`")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True, help="Tenant name key (e.g. example)")
    args = parser.parse_args()

    tenant = args.tenant
    report_md = build_report(tenant)

    ts = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    out_dir = os.path.join(REPORT_ROOT, tenant)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{ts}_AtlasReport.md")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_md)

    print(f"Report written: {out_path}")


if __name__ == "__main__":
    main()