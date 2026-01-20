# engine/detection/secure_score.py
import requests

def fetch_secure_score(headers: dict) -> dict:
    r = requests.get(
        "https://graph.microsoft.com/v1.0/security/secureScores?$top=1",
        headers=headers,
        timeout=30
    )
    r.raise_for_status()
    return r.json()["value"][0]

def fetch_control_profiles(headers: dict) -> list[dict]:
    r = requests.get(
        "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=999",
        headers=headers,
        timeout=30
    )
    r.raise_for_status()
    return r.json().get("value", [])

def build_findings(score: dict, profiles: list[dict]) -> list[dict]:
    profiles_by_id = {p["id"]: p for p in profiles}
    findings = []

    for c in score.get("controlScores", []):
        cid = c.get("controlName")
        p = profiles_by_id.get(cid)
        findings.append({
            "controlId": cid,
            "category": c.get("controlCategory"),
            "scorePct": int(float(c.get("scoreInPercentage", 0))),
            "title": p.get("title") if p else None,
            "actionUrl": p.get("actionUrl") if p else None,
            "implementationStatus": c.get("implementationStatus", ""),
        })
    return findings
