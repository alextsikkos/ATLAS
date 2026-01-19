CONTROL = {
    "id": "AdminMFAV2",
    "name": "Require MFA for admin roles",
    "tier": "Tier-1",  # you can argue Tier-2; but v1 is report-only and safe
    "requires_approval": False,  # Tier-1 = auto, but still report-only initially
    "default_mode": "report-only",
    "impact": "low",
    "secure_score_ids": ["AdminMFAV2"],
}