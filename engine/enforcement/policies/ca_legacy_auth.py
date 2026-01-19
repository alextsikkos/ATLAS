# engine/enforcement/policies/ca_legacy_auth.py

def build_ca_block_legacy_auth_policy(display_name: str, include_users: list[str]) -> dict:
    """
    Blocks legacy authentication by targeting legacy client app types.
    include_users should be ["All"] (your current reliable pattern), or a list of user IDs/groups if you later scope it.
    """
    return {
        "displayName": display_name,
        "state": "enabled",  # ensure.py should override state if running report-only vs enforce
        "conditions": {
            "users": {
                "includeUsers": include_users,
                "excludeUsers": []
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": []
            },
            "clientAppTypes": ["exchangeActiveSync", "other"]  # legacy auth buckets
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"]
        }
    }
