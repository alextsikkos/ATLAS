# engine/enforcement/policies/ca_admin_mfa_all_apps.py

DISPLAY_NAME = "ATLAS - Require MFA (Admins)"

def build_payload(mode: str = "report-only", exclude_group_id: str | None = None) -> dict:
    return {
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
            "clientAppTypes": ["all"]
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"]
        }
    }
