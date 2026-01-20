# engine/enforcement/policies/admin_phishing_resistant_mfa.py

DISPLAY_NAME = "ATLAS - Admin Phishing-resistant MFA Strength"

ADMIN_ROLE_TEMPLATE_IDS = [
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451",  # Global Reader
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # SharePoint Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
]

def build_payload(
    mode: str = "report-only",
    authentication_strength_policy_id: str | None = None,
    exclude_group_id: str | None = None
) -> dict:
    """
    Conditional Access policy for admins requiring phishing-resistant MFA
    using Authentication Strengths.

    authentication_strength_policy_id is looked up dynamically in main.py
    because IDs differ per tenant.
    """

    state = "enabled" if mode == "enforce" else "enabledForReportingButNotEnforced"

    exclude_groups = ([exclude_group_id] if exclude_group_id else [])

    grant_controls = {
        "operator": "AND",
        "authenticationStrength": {
            "id": authentication_strength_policy_id
        }
    }

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
        "grantControls": grant_controls,
    }
