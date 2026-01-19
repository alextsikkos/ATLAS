DISPLAY_NAME = "ATLAS - Risky Sign-in MFA (Report Only)"

def build_payload(mode: str = "report-only", exclude_group_id: str | None = None) -> dict:
    state = "enabledForReportingButNotEnforced" if mode == "report-only" else "enabled"

    return {
        "displayName": DISPLAY_NAME,
        "state": state,
        "conditions": {
            "signInRiskLevels": ["medium", "high"],
            "clientAppTypes": ["all"],
            "applications": {"includeApplications": ["All"]},
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "excludeGroups": ([exclude_group_id] if exclude_group_id else []),
            },
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"]
        }
    }