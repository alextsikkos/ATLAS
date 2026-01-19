import requests

BASE = "https://graph.microsoft.com/v1.0"

def list_policies(headers: dict, top: int = 50):
    r = requests.get(f"{BASE}/identity/conditionalAccess/policies?$top={top}", headers=headers, timeout=30)
    r.raise_for_status()
    return r.json().get("value", [])

def find_policy_by_name(headers, display_name):
    url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    params = {"$filter": f"displayName eq '{display_name}'", "$top": 1}

    # Retry transient Graph failures
    last_status = None
    last_text = None

    for attempt in range(1, 4):  # 3 attempts
        try:
            r = requests.get(url, headers=headers, params=params, timeout=30)
            last_status = r.status_code
            last_text = r.text

            # transient retry cases
            if r.status_code in (429, 503, 504):
                time.sleep(2.0 * attempt)
                continue

            # Non-transient errors: don't crash the run
            if r.status_code >= 400:
                return None, {
                    "ok": False,
                    "status": r.status_code,
                    "error": "Graph CA list failed",
                    "responseText": (r.text[:2000] if r.text else None),
                    "url": url,
                    "params": params,
                }

            body = r.json() if r.text else {}
            vals = body.get("value") or []
            return (vals[0] if vals else None), {
                "ok": True,
                "status": r.status_code,
                "count": len(vals),
                "url": url,
                "params": params,
            }

        except requests.exceptions.RequestException as e:
            # retry network-type failures
            time.sleep(2.0 * attempt)
            last_text = str(e)

    # If we get here, we exhausted retries
    return None, {
        "ok": False,
        "status": (last_status or 504),
        "error": "Graph CA list timed out after retries",
        "responseText": (last_text[:2000] if isinstance(last_text, str) else None),
        "url": url,
        "params": params,
    }

def create_policy(headers: dict, payload: dict):
    import requests

    r = requests.post(
        f"{BASE}/identity/conditionalAccess/policies",
        headers=headers,
        json=payload,
        timeout=30
    )

    # Always try to capture useful error info (Graph often returns JSON error bodies)
    try:
        body = r.json() if r.content else None
    except Exception:
        body = None

    return r.status_code, body, (r.text or "")


def patch_policy(headers: dict, policy_id: str, payload: dict):
    import requests

    r = requests.patch(
        f"{BASE}/identity/conditionalAccess/policies/{policy_id}",
        headers=headers,
        json=payload,
        timeout=30
    )

    try:
        body = r.json() if r.content else None
    except Exception:
        body = None

    return r.status_code, body, (r.text or "")
