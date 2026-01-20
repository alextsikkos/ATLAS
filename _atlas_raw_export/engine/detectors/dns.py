from __future__ import annotations

from typing import Any, Dict, List, Tuple

def _safe_import_dnspython():
    try:
        import dns.resolver  # type: ignore
        return dns.resolver
    except Exception:
        return None

from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

def dnspython_available() -> bool:
    return _safe_import_dnspython() is not None


def _txt_lookup(domain: str) -> List[str]:
    resolver = _safe_import_dnspython()
    if resolver is None:
        raise RuntimeError("dnspython not installed")

    answers = resolver.resolve(domain.strip("."), "TXT")
    vals: List[str] = []
    for rdata in answers:
        # rdata.strings may be bytes chunks; prefer str(rdata)
        vals.append(str(rdata).strip('"'))
    return vals


def check_spf(domain: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Checks for SPF record on <domain> TXT.

    Returns:
      (has_spf, details)
    Conservative:
      - Any resolver error is treated as has_spf=False with error detail.
    """
    try:
        txt_values = _txt_lookup(domain)
        joined = " ".join(txt_values)
        has_spf = "V=SPF1" in joined.upper()
        return has_spf, {"domain": domain, "txtCount": len(txt_values), "txt": txt_values[:5]}
    except Exception as e:
        return False, {"domain": domain, "txtCount": 0, "error": str(e)}


def bulk_check_spf(
    domains: List[str],
    *,
    max_workers: int = 10,
    per_domain_timeout_seconds: float = 2.5,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Runs SPF checks in bounded parallel.

    Returns:
      (checked_samples, missing_domains)

    Conservative:
      - Any timeout/error => missing SPF for that domain.
    """
    checked: List[Dict[str, Any]] = []
    missing: List[str] = []

    # de-dupe while preserving order
    seen = set()
    doms = []
    for d in domains:
        d = (d or "").strip().strip(".")
        if not d or d in seen:
            continue
        seen.add(d)
        doms.append(d)

    if not doms:
        return [], []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_map = {ex.submit(check_spf, d): d for d in doms}
        for fut in as_completed(fut_map):
            d = fut_map[fut]
            try:
                has_spf, det = fut.result(timeout=per_domain_timeout_seconds)
            except FuturesTimeoutError:
                has_spf, det = False, {"domain": d, "txtCount": 0, "error": f"timeout after {per_domain_timeout_seconds}s"}
            except Exception as e:
                has_spf, det = False, {"domain": d, "txtCount": 0, "error": str(e)}

            checked.append(
                {
                    "domain": d,
                    "txtCount": det.get("txtCount", 0),
                    "hasSpf": bool(has_spf),
                    "error": det.get("error"),
                }
            )

            if not has_spf:
                missing.append(d)

    return checked, missing

def check_dmarc(domain: str) -> Tuple[str, Dict[str, Any]]:
    """
    Checks for _dmarc.<domain> TXT record.

    COMPLIANT: TXT exists and contains v=DMARC1
    DRIFTED: no DMARC TXT record, or doesn't contain v=DMARC1
    ERROR: dnspython not installed / resolver failure
    """
    resolver = _safe_import_dnspython()
    if resolver is None:
        return "ERROR", {
            "reason": "dnspython not installed (pip install dnspython)",
            "domain": domain,
            "record": f"_dmarc.{domain}",
        }

    qname = f"_dmarc.{domain}".strip(".")
    try:
        answers = resolver.resolve(qname, "TXT")
        txt_values: List[str] = []
        for rdata in answers:
            # rdata.strings may be bytes chunks; prefer str(rdata)
            txt = str(rdata).strip('"')
            txt_values.append(txt)

        joined = " ".join(txt_values)
        ok = "V=DMARC1" in joined.upper()

        if ok:
            return "COMPLIANT", {
                "domain": domain,
                "record": qname,
                "txt": txt_values[:5],
            }

        return "DRIFTED", {
            "domain": domain,
            "record": qname,
            "txt": txt_values[:5],
            "reason": "DMARC record missing v=DMARC1",
        }

    except Exception as e:
        return "DRIFTED", {
            "domain": domain,
            "record": qname,
            "reason": "No DMARC TXT record found",
            "error": str(e),
        }
def dnspython_available() -> bool:
    return _safe_import_dnspython() is not None


def resolve_txt(domain: str, timeout_seconds: float = 1.5, lifetime_seconds: float = 3.0) -> List[str]:
    """
    Resolve TXT records for <domain> with bounded timeout.
    Returns list of TXT strings (best-effort). Raises on failure.
    """
    resolver_mod = _safe_import_dnspython()
    if resolver_mod is None:
        raise RuntimeError("dnspython not installed (pip install dnspython)")

    r = resolver_mod.Resolver(configure=True)
    # dnspython timeouts:
    r.timeout = float(timeout_seconds)
    r.lifetime = float(lifetime_seconds)

    answers = r.resolve(domain.strip("."), "TXT")
    out: List[str] = []
    for rdata in answers:
        out.append(str(rdata).strip('"'))
    return out


def check_spf(domain: str, timeout_seconds: float = 1.5, lifetime_seconds: float = 3.0) -> Tuple[str, Dict[str, Any]]:
    """
    Checks <domain> TXT records for v=spf1

    COMPLIANT: any TXT contains v=spf1
    DRIFTED: no TXT with v=spf1, or lookup fails (conservative)
    ERROR: dnspython missing
    """
    try:
        txt_values = resolve_txt(domain, timeout_seconds=timeout_seconds, lifetime_seconds=lifetime_seconds)
    except RuntimeError as e:
        return "ERROR", {"domain": domain, "record": domain, "reason": str(e)}
    except Exception as e:
        return "DRIFTED", {"domain": domain, "record": domain, "reason": "TXT lookup failed", "error": str(e)}

    joined = " ".join(txt_values)
    has_spf = "V=SPF1" in joined.upper()

    if has_spf:
        return "COMPLIANT", {"domain": domain, "record": domain, "txtCount": len(txt_values), "txt": txt_values[:5]}

    return "DRIFTED", {"domain": domain, "record": domain, "txtCount": len(txt_values), "txt": txt_values[:5], "reason": "No v=spf1 TXT found"}
