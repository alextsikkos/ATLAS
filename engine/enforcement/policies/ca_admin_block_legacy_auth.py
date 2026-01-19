# engine/enforcement/policies/ca_admin_block_legacy_auth.py

DISPLAY_NAME = "ATLAS - Block Legacy Auth (Admins)"

def build_payload(mode: str = "report-only", exclude_group_id: str | None = None) -> dict:
    # NOTE: per your current reliability rule, we scope includeUsers=["All"] (not roles) for v1.
    # You can tighten later once role scoping is stable.
    payload = {
        "displayName": DISPLAY_NAME,
        "state": "enabled" if mode == "enforce" else "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "excludeGroups": ([exclude_group_id] if exclude_group_id else []),
            },

            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": []
            },
            # Legacy auth buckets
            "clientAppTypes": ["exchangeActiveSync", "other"]
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"]
        }
    }
    return payload
