# engine/enforcement/policies/block_legacy_auth.py

DISPLAY_NAME = "ATLAS - Block Legacy Authentication"

def build_payload(mode: str = "report-only", exclude_group_id: str | None = None) -> dict:
    """
    Conditional Access policy: block legacy authentication.

    Legacy auth is blocked by targeting clientAppTypes = ["exchangeActiveSync", "other"]
    which is Microsoft's standard CA pattern for legacy auth blocking.
    """
    state = "enabled" if mode == "enforce" else "enabledForReportingButNotEnforced"

    return {
        "displayName": DISPLAY_NAME,
        "state": state,
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "excludeGroups": ([exclude_group_id] if exclude_group_id else []),
            },

            "applications": {
                "includeApplications": ["All"],
            },
            "clientAppTypes": [
                "exchangeActiveSync",
                "other"
            ],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"]
        }
    }
