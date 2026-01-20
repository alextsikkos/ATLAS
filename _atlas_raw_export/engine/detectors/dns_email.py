from typing import Tuple, Dict, Any, List
import requests

from engine.auth.token import graph_headers


def _list_custom_domains(tenant: Dict[str, Any]) -> List[str]:
    """
    Uses Graph: GET https://graph.microsoft.com/v1.0/domains
    Returns verified custom domains excluding *.onmicrosoft.com
    """
    headers = graph_headers(tenant)
    url = "https://graph.microsoft.com/v1.0/domains"

    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"Graph /domains failed (status={r.status_code}): {r.text[:2000]}")

    data = r.json()
    domains = []
    for d in data.get("value", []) or []:
        name = (d.get("id") or "").lower().strip()
        if not name:
            continue
        if name.endswith(".onmicrosoft.com"):
            continue
        if d.get("isVerified") is False:
            continue
        domains.append(name)

    return sorted(set(domains))


def _dns_google_resolve(name: str, rtype: str) -> List[Dict[str, Any]]:
    r = requests.get(
        "https://dns.google/resolve",
        params={"name": name, "type": rtype},
        timeout=10,
    )
    r.raise_for_status()
    j = r.json()
    return j.get("Answer") or []


def _has_cname(name: str) -> bool:
    answers = _dns_google_resolve(name, "CNAME")
    return len(answers) > 0


def _get_txt_strings(name: str) -> List[str]:
    answers = _dns_google_resolve(name, "TXT")
    out: List[str] = []
    for a in answers:
        data = a.get("data")
        if isinstance(data, str) and data:
            out.append(data.strip())
    return out


def detect_dkim_enabled_all_domains(tenant: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    COMPLIANT = every custom domain has at least one DKIM selector CNAME (selector1 or selector2).
    DRIFTED   = any domain missing both selector1 and selector2.
    ERROR     = Graph/DNS failure
    """
    try:
        domains = _list_custom_domains(tenant)
    except Exception as e:
        return "ERROR", {"reason": "Failed listing domains from Graph", "error": str(e)}

    if not domains:
        return "COMPLIANT", {
            "reason": "No verified custom domains found (excluding *.onmicrosoft.com).",
            "domainsChecked": 0,
        }

    missing = []
    ok = []

    for dom in domains:
        s1 = f"selector1._domainkey.{dom}"
        s2 = f"selector2._domainkey.{dom}"

        try:
            has1 = _has_cname(s1)
            has2 = _has_cname(s2)
        except Exception as e:
            missing.append({"domain": dom, "error": str(e)})
            continue

        if has1 or has2:
            ok.append({"domain": dom, "selector1": has1, "selector2": has2})
        else:
            missing.append({"domain": dom, "selector1": False, "selector2": False})

    state = "COMPLIANT" if len(missing) == 0 else "DRIFTED"
    return state, {
        "domainsChecked": len(domains),
        "okCount": len(ok),
        "missingCount": len(missing),
        "missing": missing[:25],
        "notes": "Checks CNAME existence for selector1/selector2._domainkey.<domain> via dns.google",
    }


def detect_dmarc_all_domains(tenant: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    COMPLIANT = every custom domain has a _dmarc.<domain> TXT containing v=DMARC1
    DRIFTED   = any domain missing it.
    ERROR     = Graph/DNS failure
    """
    try:
        domains = _list_custom_domains(tenant)
    except Exception as e:
        return "ERROR", {"reason": "Failed listing domains from Graph", "error": str(e)}

    if not domains:
        return "COMPLIANT", {
            "reason": "No verified custom domains found (excluding *.onmicrosoft.com).",
            "domainsChecked": 0,
        }

    missing = []
    ok = []

    for dom in domains:
        name = f"_dmarc.{dom}"
        try:
            txts = _get_txt_strings(name)
        except Exception as e:
            missing.append({"domain": dom, "error": str(e)})
            continue

        # Any TXT record containing v=DMARC1 is sufficient
        has = any("V=DMARC1" in t.upper() for t in txts)

        if has:
            ok.append({"domain": dom, "records": txts[:5]})
        else:
            missing.append({"domain": dom, "recordsFound": txts[:5]})

    state = "COMPLIANT" if len(missing) == 0 else "DRIFTED"
    return state, {
        "domainsChecked": len(domains),
        "okCount": len(ok),
        "missingCount": len(missing),
        "missing": missing[:25],
        "notes": "Checks TXT existence for _dmarc.<domain> via dns.google and looks for v=DMARC1",
    }
