# engine/controls/identity/risky_signin_mfa.py

CONTROL = {
    "id": "SigninRiskPolicy",
    "name": "Require MFA for risky sign-ins",
    "tier": "Tier-2",
    "requires_approval": True,
    "default_mode": "report-only",
    "impact": "medium",
    "secure_score_ids": ["SigninRiskPolicy"],
}

def is_applicable(tenant_config: dict) -> bool:
    # later: check licensing, exclusions, etc.
    return True
