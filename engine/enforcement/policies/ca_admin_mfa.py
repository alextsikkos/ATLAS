# engine/enforcement/policies/ca_admin_mfa.py

def build_ca_admin_mfa_all_apps_policy(display_name: str, include_users: list[str]) -> dict:
    """
    Requires MFA for the target set (admins conceptually, but we use includeUsers=["All"] for reliability per your rule).
    """
    return {
        "displayName": display_name,
        "state": "enabled",
        "conditions": {
            "users": {
                "includeUsers": include_users,
                "excludeUsers": []
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
