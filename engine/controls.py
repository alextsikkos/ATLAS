import argparse
from typing import Any, Dict, List

from engine.registry.loader import load_controls


def _yn(v) -> str:
    return "yes" if v else "no"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier", type=int, help="Filter by tier (e.g. 1 or 2)")
    parser.add_argument("--category", help="Filter by category (e.g. Identity)")
    args = parser.parse_args()

    controls: List[Dict[str, Any]] = load_controls()

    # Optional filters
    if args.tier is not None:
        controls = [c for c in controls if c.get("tier") == args.tier]
    if args.category:
        controls = [c for c in controls if str(c.get("category", "")).lower() == args.category.lower()]

    # Sort for stable output
    controls = sorted(controls, key=lambda c: c.get("id", ""))

    print("Atlas controls (registry)")
    print("")
    print(f"Total: {len(controls)}")
    print("")

    # Header
    print(f"{'ID':30} {'Tier':>4} {'Category':12} {'Approval':9} {'Secure Score mappings'}")
    print("-" * 100)

    for c in controls:
        cid = c.get("id", "")
        tier = c.get("tier", "")
        category = c.get("category", "")
        approval_required = c.get("approvalRequired", False) or (tier == 2)
        ss = c.get("secureScoreControlIds", []) or []
        ss_str = ", ".join(ss)

        print(f"{cid:30} {str(tier):>4} {str(category):12} {_yn(approval_required):9} {ss_str}")

    print("")
    print("Notes:")
    print("- Approval defaults to 'yes' for Tier 2 if approvalRequired is not explicitly set.")


if __name__ == "__main__":
    main()