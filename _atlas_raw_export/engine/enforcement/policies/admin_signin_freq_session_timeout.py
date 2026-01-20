# engine/enforcement/policies/admin_signin_freq_session_timeout.py

DISPLAY_NAME = "ATLAS - Admin Sign-in Frequency + Non-persistent Browser Sessions"

def build_payload(
    mode: str = "report-only",
    exclude_group_id: str | None = None
) -> dict:
    """
    Conditional Access policy for admins:
    - Sign-in frequency enabled
    - Persistent browser session = Never
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
            "clientAppTypes": ["all"],
        },
        "sessionControls": {
            "signInFrequency": {
                "type": "hours",
                "value": 1,
                "isEnabled": True,
            },
            "persistentBrowser": {
                "mode": "never",
                "isEnabled": True,
            },
        },
    }
