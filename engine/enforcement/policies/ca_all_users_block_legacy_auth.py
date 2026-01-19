# engine/enforcement/policies/ca_all_users_block_legacy_auth.py

DISPLAY_NAME = "ATLAS - Block Legacy Auth (All Users)"

def build_payload(mode: str = "report-only", exclude_group_id: str | None = None) -> dict:
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
            "clientAppTypes": ["exchangeActiveSync", "other"]
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"]
        }
    }
    return payload
