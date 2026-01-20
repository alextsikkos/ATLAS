# engine/enforcement/policies/admin_mfa.py

DISPLAY_NAME_REPORT_ONLY = "ATLAS - Admin MFA (Report Only)"
DISPLAY_NAME_ENFORCE = "ATLAS - Admin MFA"
# Backwards-compatible alias (engine.main imports DISPLAY_NAME)
DISPLAY_NAME = DISPLAY_NAME_REPORT_ONLY


# Keep your role IDs exactly as you already used in the script (v1).
ADMIN_ROLE_IDS = [
    "62e90394-69f5-4237-9190-012177145e10",  # Global Admin
    "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",
    "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8"
]

def build_payload(
    mode: str = "report-only",
    exclude_group_id: str | None = None,
    exclude_user_ids: list[str] | None = None
) -> dict:
    """
    ATLAS Admin MFA policy (Report-only or Enforce).
    Supports both exclude_user_ids (legacy) and exclude_group_id (preferred).
    """
    state = "enabledForReportingButNotEnforced" if mode == "report-only" else "enabled"

    exclude_user_ids = exclude_user_ids or []
    exclude_groups = ([exclude_group_id] if exclude_group_id else [])

    return {
        "displayName": (DISPLAY_NAME_REPORT_ONLY if mode == "report-only" else DISPLAY_NAME_ENFORCE),
        "state": state,
        "conditions": {
            "clientAppTypes": ["all"],
            "applications": {"includeApplications": ["All"]},
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": exclude_user_ids,
                "excludeGroups": exclude_groups,
            },
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"]
        }
    }
