import json
import subprocess
from pathlib import Path
from typing import Tuple, Dict, Any
# Global per-run cache (survives tenant dict copies)
# Keyed by tenant_domain so snapshot fan-out is paid once per tenant per run.
_GLOBAL_EXO_PS_CACHE: Dict[str, Dict[str, Any]] = {}
# Process-wide IPP capability cache (if local cmdlets are missing, don't even start PowerShell again)
_GLOBAL_IPP_PREFLIGHT: Dict[str, Any] = {}


def _is_true(v) -> bool:
    return str(v).strip().lower() == "true"


def _run_exo_ps(script_name: str, tenant: dict, timeout_s: int = 240) -> Tuple[bool, Dict[str, Any]]:
    """
    Runs an EXO/IPP PowerShell detector script and returns:
      (ok, payload)

    ok=False payload includes stderr/stdout and reason.
    ok=True  payload is parsed JSON from stdout.

    Additive optimization:
      - Per-run in-memory cache (tenant["_exo_ps_cache"])
      - Snapshot fan-out via exo_snapshot.ps1 (single EXO connection, multiple signals)
    """
    tenant_domain = tenant.get("tenant_domain")
    if not tenant_domain:
        return False, {"reason": "tenant_domain missing from tenant config (e.g. contoso.onmicrosoft.com)"}

    # Per-run in-memory cache (main.py seeds tenant["_exo_ps_cache"] = {})
    # Use a global cache keyed by tenant_domain so caching works even if the engine
    # passes a copy of the tenant dict into each control.
    cache = _GLOBAL_EXO_PS_CACHE.setdefault(tenant_domain, {})
    tenant["_exo_ps_cache"] = cache  # keep backward compatibility
    # -----------------------------
    # AntiPhishPolicy per-run memoization
    # Many MDO controls call different PS scripts that all run Get-AntiPhishPolicy.
    # We alias them to ONE shared cache key + ONE superset script so we pay the cmdlet once per run.
    # -----------------------------
    _ANTIPHISH_SCRIPTS = {
        "mdo_anti_phishing_policies_tuned.ps1",
        "mdo_mailbox_intelligence_actions_configured.ps1",
        "mdo_mailbox_intelligence_protection.ps1",
        "mdo_targeted_users_protection.ps1",
        "mdo_targeted_domain_protection.ps1",
        "mdo_targeted_protection.ps1",
        "mdo_targeted_domain_protection_action.ps1",
        "mdo_targeted_user_protection_action.ps1",
        "mdo_phish_threshold_level.ps1",
        "mdo_safety_tips_enabled.ps1",
        "exo_anti_phish.ps1",
    }

    script_cache_key = script_name
    script_exec_name = script_name

    if script_name in _ANTIPHISH_SCRIPTS:
        # Use the superset script (already returns a broad set of AntiPhishPolicy fields).
        script_cache_key = "_antiphish_policy_bundle"
        script_exec_name = "mdo_anti_phishing_policies_tuned.ps1"

    # Fast return if we already have this script cached (prevents re-running snapshot per control)
    cached = cache.get(script_cache_key)
    if isinstance(cached, dict):
        if cached.get("connected") is False:
            return False, cached
        return True, cached

    # If IPPSSession is known-unavailable for this run, fail fast for all ipp_* scripts.
    if script_name.startswith("ipp_"):
        ipp_fail = cache.get("_ipp_unavailable")
        if isinstance(ipp_fail, dict):
            return False, ipp_fail

    # If we already have the payload for this script, return it immediately
    if script_cache_key in cache and isinstance(cache.get(script_cache_key), dict):
        cached = cache[script_cache_key]
        if cached.get("connected") is False:
            if "reason" not in cached:
                cached = {**cached, "reason": cached.get("error") or "EXO cached failure"}
                cache[script_name] = cached
            return False, cached
        return True, cached


    exo = tenant.get("exo", {}) or {}

    # Be tolerant to tenant JSON key variants (prevents snapshot being skipped)
    app_id = (
        exo.get("appId")
        or exo.get("AppId")
        or exo.get("appid")
        or exo.get("APPID")
        or ""
    )

    thumb = (
        exo.get("certThumbprint")
        or exo.get("CertThumbprint")
        or exo.get("cert_thumbprint")
        or exo.get("thumbprint")
        or exo.get("Thumbprint")
        or ""
    )


    ps_script = Path("engine") / "detectors" / script_exec_name
    if not ps_script.exists():
        return False, {"reason": f"Missing PowerShell script: {ps_script}"}
    # Ensure we only attempt exo_snapshot once per run per tenant (prevents runaway re-snapshotting).
    snapshot_attempted = bool(cache.get("_exo_snapshot_attempted"))
    # Fast return from cache BEFORE attempting snapshot (otherwise we'd pay snapshot cost per control).
    cached = cache.get(script_cache_key)
    if isinstance(cached, dict):
        if cached.get("connected") is False:
            return False, cached
        return True, cached

    # --- Snapshot fan-out (fast path) ---
    # Only attempt snapshot for known EXO/MDO scripts (keeps behavior conservative).
    try:
        wants_snapshot = script_name.startswith(("exo_", "mdo_"))
        snapshot_script = Path("engine") / "detectors" / "exo_snapshot.ps1"

        def _extract_json_from_stdout(raw: str) -> str | None:
            """
            Extract the JSON object emitted by exo_snapshot.ps1 even if stdout contains
            extra noise (warnings, banners, etc.).
            We look for a JSON object that parses and contains a top-level "scripts" key.
            """
            if not isinstance(raw, str):
                return None
            s = raw.strip()
            if not s:
                return None

            # Fast path: pure JSON
            try:
                obj = json.loads(s)
                if isinstance(obj, dict) and "scripts" in obj:
                    return s
            except Exception:
                pass

            # Heuristic: scan possible JSON objects from the end backwards
            opens = [i for i, ch in enumerate(s) if ch == "{"]

            for start in reversed(opens):
                candidate = s[start:].strip()

                end = candidate.rfind("}")
                if end == -1:
                    continue
                candidate = candidate[: end + 1].strip()

                if not (candidate.startswith("{") and candidate.endswith("}")):
                    continue

                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict) and "scripts" in obj:
                        return candidate
                except Exception:
                    continue

            return None

        if wants_snapshot and snapshot_script.exists() and not snapshot_attempted:
            cmd = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(snapshot_script),
                "-TenantDomain",
                tenant_domain,
            ]
            if app_id and thumb:
                cmd += ["-AppId", app_id, "-CertThumbprint", thumb]

            snapshot_timeout_s = max(int(timeout_s or 0), 600)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=snapshot_timeout_s)

            if proc.returncode == 0:
                json_text = _extract_json_from_stdout(proc.stdout or "")
                snap = json.loads(json_text) if json_text else None

                # IMPORTANT: only mark attempted after a successful parse
                if isinstance(snap, dict) and isinstance(snap.get("scripts"), dict):
                    # NOTE: don't mark snapshot attempted until we can parse it, otherwise we "burn" the snapshot path
                    cmd = [
                        "powershell",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(snapshot_script),
                        "-TenantDomain",
                        tenant_domain,
                    ]
                    if app_id and thumb:
                        cmd += ["-AppId", app_id, "-CertThumbprint", thumb]

                    snapshot_timeout_s = max(int(timeout_s or 0), 600)
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=snapshot_timeout_s)

                    if proc.returncode == 0:
                        raw = (proc.stdout or "").strip()
                        if raw:
                            def _extract_snapshot_json(raw_stdout: str) -> str | None:
                                """
                                exo_snapshot.ps1 SHOULD emit a single JSON object, but PowerShell can still
                                leak warnings/noise. We only accept a JSON object that parses AND contains "scripts".
                                """
                                if not isinstance(raw_stdout, str):
                                    return None
                                s = raw_stdout.strip()
                                if not s:
                                    return None

                                # Fast path: whole stdout is JSON
                                try:
                                    obj = json.loads(s)
                                    if isinstance(obj, dict) and "scripts" in obj:
                                        return s
                                except Exception:
                                    pass

                                # Fallback: scan for candidate JSON objects from the end backwards
                                opens = [i for i, ch in enumerate(s) if ch == "{"]

                                for start in reversed(opens):
                                    candidate = s[start:].strip()
                                    end = candidate.rfind("}")
                                    if end == -1:
                                        continue
                                    candidate = candidate[: end + 1].strip()

                                    if not (candidate.startswith("{") and candidate.endswith("}")):
                                        continue

                                    try:
                                        obj = json.loads(candidate)
                                        if isinstance(obj, dict) and "scripts" in obj:
                                            return candidate
                                    except Exception:
                                        continue

                                return None

                            json_text = _extract_snapshot_json(proc.stdout or "")
                            snap = json.loads(json_text) if json_text else None

                            if isinstance(snap, dict) and isinstance(snap.get("scripts"), dict):
                                # Mark attempted only after we successfully parsed the snapshot payload
                                cache["_exo_snapshot_attempted"] = True
                            else:
                                # Prevent re-running snapshot over and over if parsing fails
                                cache["_exo_snapshot_attempted"] = True
                                cache["_exo_snapshot_failed"] = {
                                    "connected": False,
                                    "reason": "Failed to parse JSON snapshot payload",
                                    "stdoutHead": (raw[:2000] if isinstance(raw, str) else ""),
                                }
                                snap = None

                            scripts = (snap or {}).get("scripts") or {}

                    for k, v in scripts.items():
                        if isinstance(v, dict):
                            if v.get("connected") is False and "reason" not in v:
                                v["reason"] = v.get("error") or "EXO snapshot sub-call failed"
                            cache[k] = v

                    if script_name in cache:
                        cached = cache[script_cache_key]
                        if isinstance(cached, dict) and cached.get("connected") is False:
                            return False, cached
                        return True, cached

            # If snapshot fails or can’t be parsed, fall back to single-script below
    except Exception:
        pass


            # If snapshot failed, we fall back to running the single script below.
    except Exception:
        # Never let snapshot failures break the run; single-script call below will surface details.
        pass

    # --- Single script fallback (original behavior) ---
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ps_script),
        "-TenantDomain",
        tenant_domain,
    ]

    # App-only cert auth (required for prod). If values are present, use them.
    if app_id and thumb:
        cmd += ["-AppId", app_id, "-CertThumbprint", thumb]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        err_payload = {
            "reason": "EXO PowerShell call timed out",
            "stderr": "",
            "stdout": (getattr(e, "stdout", "") or "").strip(),
            "exitCode": None,
            "script": str(ps_script),
            "timeoutSeconds": timeout_s,
        }
        if script_name.startswith("ipp_"):
            cache["_ipp_unavailable"] = {**err_payload, "connected": False}
        return False, err_payload


    if proc.returncode != 0:
        err_payload = {
            "reason": "EXO PowerShell call failed",
            "stderr": (proc.stderr or "").strip(),
            "stdout": (proc.stdout or "").strip(),
            "exitCode": proc.returncode,
            "script": str(ps_script),
        }

        # Cache IPPSSession failures for the rest of this run (prevents paying the 10s cost twice).
        if script_name.startswith("ipp_"):
            s = (err_payload.get("stderr") or "") + " " + (err_payload.get("stdout") or "") + " " + (err_payload.get("reason") or "")
            sl = s.lower()
            if (
                "connect-ippssession" in sl
                or "ipssession" in sl
                or "get-label" in sl and "not recognized" in sl
                or "get-autosensitivitylabelpolicy" in sl and "not recognized" in sl
                or "unauthorized" in sl
                or "forbidden" in sl
                or "access is denied" in sl
                or "aadsts" in sl
            ):
                cache["_ipp_unavailable"] = {**err_payload, "connected": False, "reason": err_payload.get("reason")}

        return False, err_payload


    out = (proc.stdout or "").strip()
    if not out:
        return False, {
            "reason": "Empty stdout from EXO PowerShell",
            "stderr": (proc.stderr or "").strip(),
            "script": str(ps_script),
        }

    def _extract_json_from_ps_stdout(raw: str) -> str | None:
        if not isinstance(raw, str):
            return None
        s = raw.strip()
        if not s:
            return None

        # Pure JSON case
        if s.startswith("{") and s.endswith("}"):
            return s

        # IPP modules often print banners before emitting JSON.
        # Extract the last JSON object in the output.
        start = s.rfind("{")
        end = s.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        candidate = s[start:end + 1].strip()
        if candidate.startswith("{") and candidate.endswith("}"):
            return candidate
        return None

    json_text = _extract_json_from_ps_stdout(proc.stdout or "")
    if not json_text:
        return False, {
            "reason": "Failed to parse JSON from EXO PowerShell stdout",
            "stdout": out[:4000],
            "stderr": (proc.stderr or "").strip(),
            "script": str(ps_script),
        }

    try:
        payload = json.loads(json_text)
        # Cache IPP cmdlet-missing failures for the rest of this run (prevents paying the 10s cost twice).
        if script_name.startswith("ipp_") and isinstance(payload, dict) and payload.get("ok") is False:
            err = (payload.get("error") or "").strip()
            el = err.lower()
            if "is not recognized as the name of a cmdlet" in el:
                cache["_ipp_unavailable"] = {
                    "connected": False,
                    "reason": "IPP cmdlet missing in session",
                    "error": err,
                    "script": str(ps_script),
                }
        # Cache "IPP unavailable" when the script itself reports ok=false AND connected=false
        # (e.g. local cmdlet missing, blocked interactive login, etc.)
        if script_name.startswith("ipp_") and isinstance(payload, dict):
            if payload.get("ok") is False and payload.get("connected") is False:
                cache["_ipp_unavailable"] = {
                    **payload,
                    "connected": False,
                    "reason": payload.get("reason") or payload.get("error") or "IPPSSession unavailable (script reported connected=false)"
                }


    except Exception:
        return False, {
            "reason": "Failed to parse JSON from EXO PowerShell stdout",
            "stdout": out[:4000],
            "stderr": (proc.stderr or "").strip(),
            "script": str(ps_script),
        }

    # Save into cache for this run
    if isinstance(payload, dict):
        cache[script_cache_key] = payload

    return True, payload
def _get_purview_bundle(tenant: dict) -> tuple[bool, dict]:
    """
    Runs a single IPP/EXO PowerShell call that returns both Purview signals:
      - Auto-labeling policies (Get-AutoSensitivityLabelPolicy)
      - Labels (Get-Label) for best-effort Data Map scope evidence

    Fast-fail behavior:
      - If we detect local cmdlet-missing once, mark IPP unavailable process-wide
        and skip launching PowerShell for subsequent calls/tenants in this run.
    """
    # Process-wide fast fail (saves PS startup time across tenants)
    pre = _GLOBAL_IPP_PREFLIGHT.get("ipp_unavailable")
    if isinstance(pre, dict):
        return False, pre

    ok, data = _run_exo_ps("ipp_purview_bundle.ps1", tenant)

    # If the PS runner itself failed, and looks like IPP is unavailable, keep existing per-tenant caching
    if not ok:
        # If the underlying failure indicates cmdlet missing, promote to process-wide fail too
        reason = (data or {}).get("reason") or ""
        if (data or {}).get("missingCmdlet") or ("cmdlet" in reason.lower() and "missing" in reason.lower()):
            _GLOBAL_IPP_PREFLIGHT["ipp_unavailable"] = data
        return False, data

    # Bundle script returns top-level ok=True even when nested signals are missing.
    # Detect nested cmdlet-missing and promote it to a hard fast-fail for the rest of this run.
    if isinstance(data, dict):
        auto = (data.get("autoLabeling") or {}) if isinstance(data.get("autoLabeling"), dict) else {}
        dm = (data.get("dataMapScope") or {}) if isinstance(data.get("dataMapScope"), dict) else {}

        # If either signal reports missingCmdlet / ok=false due to local module, treat IPP as unavailable.
        missing = auto.get("missingCmdlet") or dm.get("missingCmdlet")
        if missing:
            fail = {
                "connected": False,
                "reason": "IPP cmdlet missing in installed ExchangeOnlineManagement module",
                "missingCmdlet": missing,
                "raw": data,
            }

            # Process-wide fast fail
            _GLOBAL_IPP_PREFLIGHT["ipp_unavailable"] = fail

            # Also set per-tenant _ipp_unavailable so _run_exo_ps() short-circuits any other ipp_* scripts
            tenant_domain = tenant.get("tenant_domain")
            if tenant_domain:
                cache = _GLOBAL_EXO_PS_CACHE.setdefault(tenant_domain, {})
                cache["_ipp_unavailable"] = fail

            return False, fail

    return True, data


def _as_list(x):
    """
    EXO PowerShell JSON can return:
      - [] (no results)
      - {} (single object)
      - [ {}, {} ] (array)
    Normalize to a list of dicts.
    """
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        return [x]
    # unexpected (e.g. string) — return empty but keep raw for debugging upstream if needed
    return []



def detect_audit_log_search_enabled_status(tenant: dict) -> dict:
    """
    AuditLogSearchEnabled (Unified Audit Log ingestion enabled)
    Detect-only via Exchange Online PowerShell (Get-AdminAuditLogConfig).
    """
    try:
        ok, data = _run_exo_ps("exo_audit_log_search_enabled.ps1", tenant)
        if not ok:
            # data already contains reason/stderr/stdout/exitCode on failure
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "DETECTOR_ERROR",
                "reasonDetail": f"EXO detector failed: {data.get('reason')}",
                "details": data,
            }

        enabled = (data or {}).get("unifiedAuditLogIngestionEnabled")

        details = {
            "unifiedAuditLogIngestionEnabled": enabled,
        }

        if enabled is None:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_DATA",
                "reasonDetail": "EXO did not return unifiedAuditLogIngestionEnabled",
                "details": {**details, "missingKeys": ["unifiedAuditLogIngestionEnabled"]},
            }

        state = "COMPLIANT" if _is_true(enabled) else "DRIFTED"
        return {
            "state": state,
            "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
            "reasonDetail": "Evaluated via Exchange Online (Get-AdminAuditLogConfig)",
            "details": details,
        }

    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "DETECTOR_ERROR",
            "reasonDetail": f"Exception: {e}",
            "details": {"exception": str(e)},
        }
def detect_mailbox_auditing_enabled_status(tenant: dict) -> dict:
    """
    MailboxAuditingEnabled
    Detect-only via Exchange Online PowerShell (Get-OrganizationConfig + Get-EXOMailbox -PropertySets Audit).

    Conservative behavior:
      - NOT_EVALUATED if required signals are missing (we do not guess)
      - DRIFTED if org auditing is disabled OR any mailboxes report AuditEnabled == false
      - COMPLIANT otherwise

    Notes:
      - bypass associations are collected as info-only and do not change compliance state.
    """
    try:
        ok, data = _run_exo_ps("exo_mailbox_auditing_enabled.ps1", tenant)
        if not ok:
            # Conservative: if EXO/PS failed to connect or run cmdlets, treat as missing signal not a hard crash.
            # We still surface full evidence in details (no hiding).
            rc = "MISSING_SIGNAL" if (data or {}).get("connected") is False else "DETECTOR_ERROR"
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": rc,
                "reasonDetail": f"EXO mailbox auditing signal unavailable: {data.get('reason') or data.get('error')}",
                "details": data,
            }


        audit_disabled = (data or {}).get("auditDisabled")
        mbx_disabled_count = (data or {}).get("mailboxesAuditingDisabledCount")

        details = {
            "auditDisabled": audit_disabled,
            "mailboxesAuditingDisabledCount": mbx_disabled_count,
            "mailboxesAuditingDisabledSamples": (data or {}).get("mailboxesAuditingDisabledSamples") or [],
            "bypassAssociationsCount": (data or {}).get("bypassAssociationsCount"),
            "bypassAssociationsSamples": (data or {}).get("bypassAssociationsSamples") or [],
            "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
            "errors": (data or {}).get("errors") or {},
        }

        missing = []
        if audit_disabled is None:
            missing.append("auditDisabled")
        if mbx_disabled_count is None:
            missing.append("mailboxesAuditingDisabledCount")

        if mbx_disabled_count is not None and not isinstance(mbx_disabled_count, (int, float)):
            missing.append("mailboxesAuditingDisabledCount")

        if missing:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_DATA",
                "reasonDetail": "EXO did not return required mailbox auditing signals",
                "details": {**details, "missingKeys": sorted(list(set(missing)))},
            }

        drifted = _is_true(audit_disabled) or int(mbx_disabled_count) > 0
        state = "DRIFTED" if drifted else "COMPLIANT"

        rd = "Evaluated via Exchange Online (Get-OrganizationConfig + Get-EXOMailbox)"
        bypass_cnt = details.get("bypassAssociationsCount")
        if isinstance(bypass_cnt, (int, float)) and bypass_cnt > 0:
            rd += f"; {int(bypass_cnt)} mailbox audit bypass association(s) detected (info-only)"

        return {
            "state": state,
            "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
            "reasonDetail": rd,
            "details": details,
        }

    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "DETECTOR_ERROR",
            "reasonDetail": f"Exception in MailboxAuditingEnabled detector: {e}",
            "details": {"exception": str(e)},
        }
def detect_exo_mailtips_enabled_status(tenant: dict) -> dict:
    """
    EXOMailTipsEnabled (Secure Score: exo_mailtipsenabled)
    Detect-only via Get-OrganizationConfig.
    Conservative: NOT_EVALUATED if required signals missing.
    """
    try:
        ok, data = _run_exo_ps("exo_mailtips_enabled.ps1", tenant)
        if not ok:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "DETECTOR_ERROR",
                "reasonDetail": f"EXO detector failed: {data.get('reason')}",
                "details": data,
            }

        # Prefer the single "all tips" flag when present; else evaluate the component flags conservatively.
        all_enabled = (data or {}).get("MailTipsAllTipsEnabled")

        ext = (data or {}).get("MailTipsExternalRecipientsTipsEnabled")
        grp = (data or {}).get("MailTipsGroupMetricsEnabled")
        mbox = (data or {}).get("MailTipsMailboxSourcedTipsEnabled")
        thr = (data or {}).get("MailTipsLargeAudienceThreshold")

        details = {
            "MailTipsAllTipsEnabled": all_enabled,
            "MailTipsExternalRecipientsTipsEnabled": ext,
            "MailTipsGroupMetricsEnabled": grp,
            "MailTipsMailboxSourcedTipsEnabled": mbox,
            "MailTipsLargeAudienceThreshold": thr,
            "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
            "errors": (data or {}).get("errors") or {},
        }

        missing = []
        # If "all tips" exists, it is sufficient.
        if all_enabled is None:
            # Otherwise require the component flags to avoid guessing.
            for k, v in [
                ("MailTipsExternalRecipientsTipsEnabled", ext),
                ("MailTipsGroupMetricsEnabled", grp),
                ("MailTipsMailboxSourcedTipsEnabled", mbox),
            ]:
                if v is None:
                    missing.append(k)

        if missing:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_DATA",
                "reasonDetail": "EXO did not return required MailTips properties",
                "details": {**details, "missingKeys": sorted(list(set(missing)))},
            }

        # Evaluate compliance:
        # - If AllTipsEnabled exists: use it.
        # - Else: require all three component toggles True (threshold is informational).
        if all_enabled is not None:
            compliant = _is_true(all_enabled)
            eval_basis = "MailTipsAllTipsEnabled"
        else:
            compliant = _is_true(ext) and _is_true(grp) and _is_true(mbox)
            eval_basis = "component MailTips flags"

        state = "COMPLIANT" if compliant else "DRIFTED"

        return {
            "state": state,
            "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
            "reasonDetail": f"Evaluated via Exchange Online (Get-OrganizationConfig) using {eval_basis}",
            "details": details,
        }

    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "DETECTOR_ERROR",
            "reasonDetail": f"Exception in EXOMailTipsEnabled detector: {e}",
            "details": {"exception": str(e)},
        }
def detect_customer_lockbox_enabled_status(tenant: dict) -> dict:
    """
    CustomerLockboxEnabled (Secure Score: CustomerLockBoxEnabled)
    Detect-only via Get-OrganizationConfig.CustomerLockBoxEnabled.
    Conservative: NOT_EVALUATED if signal missing.
    """
    try:
        # Fast-path: try to reuse org-config data from exo_mailtips_enabled.ps1 (same Get-OrganizationConfig call)
        ok, data = _run_exo_ps("exo_mailtips_enabled.ps1", tenant)
        if ok:
            val = (data or {}).get("CustomerLockBoxEnabled", None)
            if val is not None:
                enabled = _is_true(val)
                return {
                    "state": "COMPLIANT" if enabled else "DRIFTED",
                    "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
                    "reasonDetail": "Evaluated via EXO OrganizationConfig (CustomerLockBoxEnabled) reusing exo_mailtips_enabled.ps1 output.",
                    "details": {
                        "CustomerLockBoxEnabled": val,
                        "enabled_normalized": enabled,
                        "sourceScript": "exo_mailtips_enabled.ps1",
                        "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
                        "errors": (data or {}).get("errors") or {},
                    },
                }

        # Fallback: dedicated script (conservative)
        ok, data = _run_exo_ps("exo_customer_lockbox_enabled.ps1", tenant)
        if not ok:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "DETECTOR_ERROR",
                "reasonDetail": f"EXO detector failed: {data.get('reason')}",
                "details": data,
            }

        val = (data or {}).get("CustomerLockBoxEnabled", None)



        if val is None:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_SIGNAL",
                "reasonDetail": "CustomerLockBoxEnabled was not returned by Get-OrganizationConfig.",
                "details": {
                    "CustomerLockBoxEnabled": None,
                    "missingKeys": ["CustomerLockBoxEnabled"],
                    "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
                    "errors": (data or {}).get("errors") or {},
                },
            }

        enabled = _is_true(val)

        return {
            "state": "COMPLIANT" if enabled else "DRIFTED",
            "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
            "reasonDetail": "Evaluated via EXO OrganizationConfig (CustomerLockBoxEnabled).",
            "details": {
                "CustomerLockBoxEnabled": val,
                "enabled_normalized": enabled,
                "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
                "errors": (data or {}).get("errors") or {},
            },
        }

    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "DETECTOR_ERROR",
            "reasonDetail": f"Exception evaluating CustomerLockboxEnabled: {e}",
            "details": {"error": str(e)},
        }
def detect_purview_auto_labeling_policies_status(tenant: dict) -> dict:
    """
    PurviewAutoLabelingPolicies (Secure Score: mip_autosensitivitylabelspolicies)
    Signal: Get-AutoSensitivityLabelPolicy (Security & Compliance PowerShell).
    Conservative:
      - COMPLIANT if >=1 policy exists
      - DRIFTED if 0 policies exist
      - NOT_EVALUATED on error / missing data
    """
    try:
        ok, data = _get_purview_bundle(tenant)
        if not ok:
            missing = (data or {}).get("missingCmdlet")
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_SIGNAL" if missing else "DETECTOR_ERROR",
                "reasonDetail": (data or {}).get("reason") or (data or {}).get("error") or "Purview/IPP signal unavailable",
                "details": data,
            }

        # Script may return JSON with ok=false (e.g., missing cmdlet / blocked auth) while the PS run itself succeeded.
        if isinstance(data, dict) and data.get("ok") is False:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_SIGNAL" if data.get("missingCmdlet") else "DETECTOR_ERROR",
                "reasonDetail": data.get("reason") or data.get("error") or "Purview/IPP signal unavailable",
                "details": data,
            }
        # Support both shapes:
        #  - bundle shape: { autoLabeling: { policyCount, policies }, ... }
        #  - direct script shape: { policyCount, policies, ... }
        section = (data or {}).get("autoLabeling") or {}
        cnt = (data or {}).get("policyCount", None)
        if cnt is None:
            cnt = section.get("policyCount", None)

        policies = (data or {}).get("policies")
        if policies is None:
            policies = section.get("policies")



        if cnt is None:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_SIGNAL",
                "reasonDetail": "IPPSSession did not return policyCount.",
                "details": {"raw": data, "missingKeys": ["policyCount"]},
            }

        return {
            "state": "COMPLIANT" if int(cnt) > 0 else "DRIFTED",
            "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
            "reasonDetail": "Evaluated via IPPSSession Get-AutoSensitivityLabelPolicy.",
            "details": {
                "policyCount": int(cnt),
                "policies": policies or [],
            },
        }

    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "DETECTOR_ERROR",
            "reasonDetail": f"Exception evaluating PurviewAutoLabelingPolicies: {e}",
            "details": {"error": str(e)},
        }


def detect_purview_label_consent_datamap_status(tenant: dict) -> dict:
    """
    PurviewLabelConsentDataMap (Secure Score: mip_purviewlabelconsent)
    We do NOT currently have a guaranteed, stable admin API for the "consent" toggle itself.
    So we do the most conservative thing:
      - Pull labels via Get-Label (IPPSSession) and attempt to find a clear 'Files & other data assets' scope signal.
      - If we cannot unambiguously determine that scope from returned fields, return NOT_EVALUATED with raw evidence.
    """
    try:
        ok, data = _get_purview_bundle(tenant)
        if not ok:
            missing = (data or {}).get("missingCmdlet")
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_SIGNAL" if missing else "DETECTOR_ERROR",
                "reasonDetail": (data or {}).get("reason") or (data or {}).get("error") or "Purview/IPP signal unavailable",
                "details": data,
            }

        # Script may return JSON with ok=false (e.g., missing cmdlet / blocked auth) while the PS run itself succeeded.
        if isinstance(data, dict) and data.get("ok") is False:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_SIGNAL" if data.get("missingCmdlet") else "DETECTOR_ERROR",
                "reasonDetail": data.get("reason") or data.get("error") or "Purview/IPP signal unavailable",
                "details": data,
            }

        # Support both shapes:
        #  - bundle shape: { labels: { labelCount, labels: [...] } }
        #  - direct script shape: { labelCount, labels: [...] }
        section = (data or {}).get("labels")
        if section is None:
            section = data or {}

        labels = (section or {}).get("labels") or []
        label_count = (section or {}).get("labelCount")
        if label_count is None:
            label_count = len(labels)


        # Attempt to detect scope from ContentType if present (string/array varies by tenant/module versions).
        scoped_hits = []
        unknown = []

        for l in labels:
            ct = l.get("ContentType")
            # Normalize to string for searching
            s = ""
            if ct is None:
                unknown.append(l.get("DisplayName") or l.get("Name"))
                continue
            if isinstance(ct, list):
                s = " ".join([str(x) for x in ct])
            else:
                s = str(ct)

            sl = s.lower()
            # Heuristic: any explicit mention of "file" or "data asset" indicates the label is scoped for files/assets.
            if ("file" in sl) or ("data asset" in sl) or ("files & other data assets" in sl):
                scoped_hits.append({
                    "DisplayName": l.get("DisplayName"),
                    "Name": l.get("Name"),
                    "ImmutableId": l.get("ImmutableId"),
                    "ContentType": ct,
                })

        if len(scoped_hits) == 0:
            # We can't safely say "drifted" because the consent toggle might exist even without labels,
            # but we *can* say we found no evidence of file/asset-scoped labels.
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "INSUFFICIENT_SIGNAL",
                "reasonDetail": "Unable to confirm Data Map labeling consent via stable API; no clear evidence of file/asset-scoped sensitivity labels found in Get-Label output.",
                "details": {
                    "labelCount": label_count,
                    "scopedLabelEvidence": [],
                    "unknownContentTypeLabels": unknown[:50],
                },
            }

        # If we have explicit evidence of file/asset-scoped labels, treat as best-available compliance evidence.
        return {
            "state": "COMPLIANT",
            "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
            "reasonDetail": "Best-available evaluation via IPPSSession Get-Label; found sensitivity labels scoped to files/data assets (required for Data Map labeling).",
            "details": {
                "labelCount": label_count,
                "scopedLabelEvidence": scoped_hits[:50],
            },
        }

    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "DETECTOR_ERROR",
            "reasonDetail": f"Exception evaluating PurviewLabelConsentDataMap: {e}",
            "details": {"error": str(e)},
        }

def detect_exo_storage_providers_restricted_status(tenant: dict) -> dict:
    """
    EXOStorageProvidersRestricted (Secure Score: exo_storageproviderrestricted)
    Detect-only via Get-OwaMailboxPolicy and property AdditionalStorageProvidersAvailable.

    Conservative:
      - NOT_EVALUATED if the property is missing for any policy (we do not guess)
      - DRIFTED if any policy has AdditionalStorageProvidersAvailable == True
      - COMPLIANT otherwise
    """
    try:
        ok, data = _run_exo_ps("exo_storage_providers_restricted.ps1", tenant)
        if not ok:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "DETECTOR_ERROR",
                "reasonDetail": f"EXO detector failed: {data.get('reason')}",
                "details": data,
            }

        policy_count = (data or {}).get("policyCount")
        enabled_count = (data or {}).get("enabledPolicyCount")
        missing_count = (data or {}).get("missingPropertyCount")

        details = {
            "policyCount": policy_count,
            "enabledPolicyCount": enabled_count,
            "enabledPolicies": (data or {}).get("enabledPolicies") or [],
            "missingPropertyCount": missing_count,
            "missingPropertyPolicies": (data or {}).get("missingPropertyPolicies") or [],
            "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
            "errors": (data or {}).get("errors") or {},
        }

        missing = []
        if policy_count is None:
            missing.append("policyCount")
        if enabled_count is None:
            missing.append("enabledPolicyCount")
        if missing_count is None:
            missing.append("missingPropertyCount")

        if missing:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_DATA",
                "reasonDetail": "EXO did not return required OWA policy signals",
                "details": {**details, "missingKeys": sorted(list(set(missing)))},
            }

        # Conservative: if ANY policies are missing the property, we refuse to guess.
        if int(missing_count) > 0:
            return {
                "state": "NOT_EVALUATED",
                "reasonCode": "MISSING_DATA",
                "reasonDetail": "AdditionalStorageProvidersAvailable property missing on one or more OWA mailbox policies",
                "details": {**details, "missingKeys": ["AdditionalStorageProvidersAvailable"]},
            }

        state = "DRIFTED" if int(enabled_count) > 0 else "COMPLIANT"

        rd = "Evaluated via Exchange Online (Get-OwaMailboxPolicy.AdditionalStorageProvidersAvailable)"
        if state == "DRIFTED":
            rd += f"; {int(enabled_count)} policy(s) allow additional storage providers"

        return {
            "state": state,
            "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
            "reasonDetail": rd,
            "details": details,
        }

    except Exception as e:
        return {
            "state": "NOT_EVALUATED",
            "reasonCode": "DETECTOR_ERROR",
            "reasonDetail": f"Exception in EXOStorageProvidersRestricted detector: {e}",
            "details": {"exception": str(e)},
        }

def detect_safe_links_status(tenant: dict) -> Tuple[str, Dict[str, Any]]:
    """
    Real detector using EXO PowerShell via engine/detectors/exo_safe_links.ps1

    Exists-anywhere logic (final):
      COMPLIANT if any active Safe Links policy exists
      DRIFTED only if no Safe Links policy exists at all
    """
    ok, data = _run_exo_ps("exo_safe_links.ps1", tenant)
    if not ok:
        return "ERROR", data

    policies = _as_list(data.get("policies"))
    rules = _as_list(data.get("rules"))

    active_policies = [
        p for p in policies
        if _is_true(p.get("EnableSafeLinksForEmail"))
        or _is_true(p.get("EnableSafeLinksForOffice"))
        or _is_true(p.get("EnableSafeLinksForTeams"))
    ]

    if active_policies:
        return "COMPLIANT", {
            "policyCount": len(policies),
            "activePolicyCount": len(active_policies),
            "ruleCount": len(rules),
            "activePolicies": [p.get("Name") for p in active_policies if p.get("Name")][:10],
            "note": "Safe Links active via policy (rules not required for built-in protection)",
        }

    return "DRIFTED", {
        "policyCount": len(policies),
        "activePolicyCount": 0,
        "ruleCount": len(rules),
        "reason": "No Safe Links policy found",
    }


def detect_safe_attachments_status(tenant: dict) -> Tuple[str, Dict[str, Any]]:
    """
    Real detector using EXO PowerShell via engine/detectors/exo_safe_attachments.ps1

    Exists-anywhere logic:
      COMPLIANT if any Safe Attachments policy exists
      DRIFTED only if no policy exists at all
    """
    ok, data = _run_exo_ps("exo_safe_attachments.ps1", tenant)
    if not ok:
        return "ERROR", data

    policies = _as_list(data.get("policies"))
    rules = _as_list(data.get("rules"))


    if len(policies) > 0:
        return "COMPLIANT", {
            "policyCount": len(policies),
            "ruleCount": len(rules),
            "policies": [p.get("Name") for p in policies if p.get("Name")][:10],
            "note": "Safe Attachments detected via policy existence (rules not required for built-in protection)",
        }

    return "DRIFTED", {
        "policyCount": 0,
        "ruleCount": len(rules),
        "reason": "No Safe Attachments policy found",
    }


def detect_anti_phish_status(tenant: dict) -> Tuple[str, Dict[str, Any]]:
    """
    Real detector using EXO PowerShell via engine/detectors/exo_anti_phish.ps1

    Exists-anywhere logic:
      COMPLIANT if any Anti-Phish policy exists
      DRIFTED only if no policy exists at all
    """
    ok, data = _run_exo_ps("exo_anti_phish.ps1", tenant)
    if not ok:
        return "ERROR", data

    policies = _as_list(data.get("policies"))
    rules = _as_list(data.get("rules"))


    if len(policies) > 0:
        return "COMPLIANT", {
            "policyCount": len(policies),
            "ruleCount": len(rules),
            "policies": [p.get("Name") for p in policies if p.get("Name")][:10],
            "note": "Anti-Phish detected via policy existence (rules not required for built-in protection)",
        }

    return "DRIFTED", {
        "policyCount": 0,
        "ruleCount": len(rules),
        "reason": "No Anti-Phish policy found",
    }
def detect_anti_spam_status(tenant: dict):
    """
    Defender for Office 365 – Anti-Spam (Hosted Content Filter)

    Exists-anywhere logic:
      COMPLIANT if any policy exists
      DRIFTED only if none exist
    """
    ok, data = _run_exo_ps("exo_anti_spam.ps1", tenant)
    if not ok:
        return "ERROR", data

    policies = _as_list(data.get("policies"))
    rules = _as_list(data.get("rules"))


    if policies:
        return "COMPLIANT", {
            "policyCount": len(policies),
            "ruleCount": len(rules),
            "policies": [p.get("Name") for p in policies][:10],
            "note": "Anti-spam policy detected (Hosted Content Filter)",
        }

    return "DRIFTED", {
        "policyCount": 0,
        "ruleCount": len(rules),
        "reason": "No anti-spam (Hosted Content Filter) policy found",
    }
def detect_anti_malware_status(tenant: dict):
    """
    Defender for Office 365 – Anti-Malware

    Exists-anywhere logic:
      COMPLIANT if any policy exists
      DRIFTED only if none exist
    """
    ok, data = _run_exo_ps("exo_anti_malware.ps1", tenant)
    if not ok:
        return "ERROR", data

    policies = _as_list(data.get("policies"))
    rules = _as_list(data.get("rules"))


    if policies:
        return "COMPLIANT", {
            "policyCount": len(policies),
            "ruleCount": len(rules),
            "policies": [p.get("Name") for p in policies][:10],
            "note": "Anti-malware policy detected",
        }

    return "DRIFTED", {
        "policyCount": 0,
        "ruleCount": len(rules),
        "reason": "No anti-malware policy found",
    }
def detect_preset_security_policies_status(tenant: dict):
    """
    Preset Security Policies (Standard/Strict/Built-in) detection.

    COMPLIANT if:
      - Strict is Enabled in BOTH EOP + ATP rules, OR
      - Standard is Enabled in BOTH EOP + ATP rules
    DRIFTED if neither Standard nor Strict is enabled across both rule types.

    Notes:
    - Built-in is informational; many tenants have it regardless.
    - We check both EOP and ATP rules because orgs with MDO typically enable both.
    """
    ok, data = _run_exo_ps("exo_preset_security_policies.ps1", tenant)
    if not ok:
        # Map common "not exposed" situations to NOT_EVALUATED (conservative Tier-3 behavior),
        # instead of surfacing as a generic ERROR.
        stderr = (data.get("stderr") or "").lower()
        stdout = (data.get("stdout") or "").lower()
        msg = f"{stderr} {stdout} {(data.get('reason') or '').lower()}"

        # Cmdlet missing typically means not licensed / feature not available in tenant.
        if (
            "get-atpprotectionpolicyrule" in msg and "not recognized" in msg
            or "get-eopprotectionpolicyrule" in msg and "not recognized" in msg
            or "is not recognized as the name of a cmdlet" in msg
        ):
            return "NOT_EVALUATED", {
                "reason": "Preset security policy cmdlets are not available in this tenant (likely licensing / feature not enabled).",
                "reasonCode": "LICENSING",
                "reasonDetail": "EOP/ATP preset security policy cmdlets missing or unavailable.",
                "details": {
                    "script": data.get("script"),
                    "exitCode": data.get("exitCode"),
                },
            }

        # Permission/access issues (app role / EXO RBAC) should be explicit.
        if ("access is denied" in msg) or ("unauthorized" in msg) or ("forbidden" in msg):
            return "NOT_EVALUATED", {
                "reason": "Insufficient permissions to read preset security policy rules in EXO.",
                "reasonCode": "PERMISSIONS",
                "reasonDetail": "EXO denied access to EOP/ATP protection policy rule retrieval.",
                "details": {
                    "script": data.get("script"),
                    "exitCode": data.get("exitCode"),
                },
            }

        return "ERROR", data


    eop_rules = _as_list(data.get("eopRules"))
    atp_rules = _as_list(data.get("atpRules"))

    def _state_for(name: str, rules: list[dict]) -> str | None:
        for r in rules:
            if (r.get("Name") or "").strip().lower() == name.strip().lower():
                return r.get("State")
        return None

    # These are the canonical rule names used by the cmdlets docs/examples
    standard_name = "Standard Preset Security Policy"
    strict_name = "Strict Preset Security Policy"
    builtin_name = "Built-in protection preset security policy"

    eop_standard = _state_for(standard_name, eop_rules)
    eop_strict = _state_for(strict_name, eop_rules)
    eop_builtin = _state_for(builtin_name, eop_rules)

    atp_standard = _state_for(standard_name, atp_rules)
    atp_strict = _state_for(strict_name, atp_rules)
    atp_builtin = _state_for(builtin_name, atp_rules)

    strict_enabled = (eop_strict == "Enabled") and (atp_strict == "Enabled")
    standard_enabled = (eop_standard == "Enabled") and (atp_standard == "Enabled")

    details = {
        "eop": {"standard": eop_standard, "strict": eop_strict, "builtin": eop_builtin},
        "atp": {"standard": atp_standard, "strict": atp_strict, "builtin": atp_builtin},
        "note": "Preset security policies are represented by EOP/ATP protection policy rules in EXO PowerShell.",
    }

    if strict_enabled:
        details["winner"] = "strict"
        return "COMPLIANT", details

    if standard_enabled:
        details["winner"] = "standard"
        return "COMPLIANT", details

    details["winner"] = None
    details["reason"] = "Neither Standard nor Strict preset security policy is enabled (EOP+ATP)."
    return "DRIFTED", details
def detect_dkim_enabled_all_domains_status(tenant: dict):
    """
    Exchange Online DKIM enabled for all custom domains (non-onmicrosoft).

    COMPLIANT: all custom domains have DKIM Enabled=True
    DRIFTED: one or more custom domains not enabled / missing config
    NOT_EVALUATED: no custom domains found
    """
    ok, data = _run_exo_ps("exo_dkim.ps1", tenant)
    if not ok:
        return "ERROR", data

    custom = _as_list(data.get("customDomains"))
    dkim = _as_list(data.get("dkim"))

    # customDomains comes back as list of strings; normalize
    custom_domains = [d for d in custom if isinstance(d, str)]

    if not custom_domains:
        return "NOT_EVALUATED", {"reason": "No custom (non-onmicrosoft) accepted domains found"}

    # dkim entries are dicts
    not_enabled = []
    enabled = []

    for entry in dkim:
        if not isinstance(entry, dict):
            continue
        domain = entry.get("Domain")
        is_enabled = bool(entry.get("Enabled"))
        if is_enabled:
            enabled.append(domain)
        else:
            not_enabled.append(domain)

    details = {
        "customDomainCount": len(custom_domains),
        "enabledCount": len([d for d in enabled if d]),
        "notEnabledCount": len([d for d in not_enabled if d]),
        "notEnabledDomains": [d for d in not_enabled if d],
    }

    if not_enabled:
        details["reason"] = "DKIM is not enabled for one or more custom domains"
        return "DRIFTED", details

    return "COMPLIANT", details
def detect_dmarc_all_domains_status(tenant: dict):
    """
    DMARC record exists for all custom accepted domains.

    COMPLIANT: all custom domains have v=DMARC1
    DRIFTED: one or more missing
    NOT_EVALUATED: no custom domains
    ERROR: dnspython missing
    """
    ok, data = _run_exo_ps("exo_dkim.ps1", tenant)  # reuse accepted domain list
    if not ok:
        return "ERROR", data

    custom = _as_list(data.get("customDomains"))
    custom_domains = [d for d in custom if isinstance(d, str)]

    if not custom_domains:
        return "NOT_EVALUATED", {"reason": "No custom (non-onmicrosoft) accepted domains found"}

    from engine.detectors.dns import check_dmarc

    results = []
    missing = []
    errors = []

    for d in custom_domains:
        st, det = check_dmarc(d)
        results.append({"domain": d, "state": st, "details": det})
        if st == "DRIFTED":
            missing.append(d)
        elif st == "ERROR":
            errors.append(d)

    if errors:
        return "ERROR", {
            "reason": "One or more DMARC checks failed",
            "errorDomains": errors,
            "results": results,
        }

    if missing:
        return "DRIFTED", {
            "reason": "DMARC missing on one or more custom domains",
            "missingDomains": missing,
            "results": results,
        }

    return "COMPLIANT", {
        "customDomainCount": len(custom_domains),
        "results": results,
    }
from typing import Any, Dict, List, Optional, Tuple

def _detector_error(script_name: str, data: dict) -> dict:
    return {
        "state": "NOT_EVALUATED",
        "reasonCode": "DETECTOR_ERROR",
        "reasonDetail": f"EXO detector failed: {data.get('reason') or data.get('error') or 'unknown error'}",
        "details": {**(data or {}), "script": script_name},
    }


def _missing_data(reason_detail: str, details: dict, missing_keys: List[str]) -> dict:
    return {
        "state": "NOT_EVALUATED",
        "reasonCode": "MISSING_DATA",
        "reasonDetail": reason_detail,
        "details": {**(details or {}), "missingKeys": sorted(list(set(missing_keys or [])))},
    }


def _policy_rows(data: dict) -> Tuple[Optional[int], List[dict]]:
    """
    Standard EXO script shape:
      { policiesCount: <int>, policies: [ {identity:.., ...}, ... ] }
    Some scripts use policyCount; we normalize.
    """
    if not isinstance(data, dict):
        return None, []
    count = data.get("policiesCount")
    if count is None:
        count = data.get("policyCount")
    rows = data.get("policies") or []
    # PowerShell ConvertTo-Json returns a dict (not a list) when there's only one item unless wrapped in @()
    if isinstance(rows, dict):
        rows = [rows]
    elif not isinstance(rows, list):
        rows = []
    return count, rows



def _sampled(rows_count: Optional[int], returned_rows: List[dict]) -> bool:
    if rows_count is None:
        return False
    return rows_count > len(returned_rows)


def _bool(v: Any) -> Optional[bool]:
    if v is None:
        return None
    return True if _is_true(v) else False

def detect_exo_calendar_external_sharing_disabled_status(tenant: dict) -> dict:
    """
    Control: EXOCalendarExternalSharingDisabled (Secure Score: exo_externalsharingdisabled)
    Script: exo_calendar_external_sharing_disabled.ps1

    COMPLIANT: enabledPolicyCount == 0
    DRIFTED: enabledPolicyCount > 0
    NOT_EVALUATED: missingDomainsPropertyCount > 0 or required signals missing
    """
    script = "exo_calendar_external_sharing_disabled.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    policy_count = (data or {}).get("policyCount")
    enabled = (data or {}).get("enabledPolicyCount")
    missing_domains = (data or {}).get("missingDomainsPropertyCount")

    details = {
        "policyCount": policy_count,
        "enabledPolicyCount": enabled,
        "enabledPolicies": (data or {}).get("enabledPolicies") or [],
        "missingDomainsPropertyCount": missing_domains,
        "missingDomainsPropertyPolicies": (data or {}).get("missingDomainsPropertyPolicies") or [],
        "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
        "errors": (data or {}).get("errors") or {},
    }

    missing = []
    if policy_count is None:
        missing.append("policyCount")
    if enabled is None:
        missing.append("enabledPolicyCount")
    if missing_domains is None:
        missing.append("missingDomainsPropertyCount")

    if missing:
        return _missing_data("EXO did not return required SharingPolicy signals", details, missing)

    if int(missing_domains) > 0:
        return _missing_data("SharingPolicy.Domains property missing on one or more policies", details, ["Domains"])

    state = "DRIFTED" if int(enabled) > 0 else "COMPLIANT"
    rd = "Evaluated via Exchange Online (Get-SharingPolicy.Domains)"
    if state == "DRIFTED":
        rd += f"; {int(enabled)} policy(s) appear to allow external/anonymous sharing"

    return {
        "state": state,
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": rd,
        "details": details,
    }


def detect_exo_outlook_addins_blocked_status(tenant: dict) -> dict:
    """
    Control: EXOOutlookAddinsBlocked (Secure Score: exo_outlookaddinsblocked)
    Script: exo_outlook_addins_blocked.ps1

    Conservative:
      - NOT_EVALUATED if no candidate properties are present.
      - If a candidate property is present:
          False => COMPLIANT (blocked)
          True  => DRIFTED (not blocked)
    """
    script = "exo_outlook_addins_blocked.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    candidates = (data or {}).get("candidates") or {}
    details = {
        "candidates": candidates,
        "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
        "errors": (data or {}).get("errors") or {},
    }

    present = {k: v for k, v in candidates.items() if v is not None}
    if not present:
        return _missing_data(
            "Get-OrganizationConfig did not return any known Outlook add-in toggle properties",
            details,
            ["OutlookAddInsEnabled/AppsForOfficeEnabled/ConnectorsEnabled (candidate properties)"],
        )

    # If ANY present property indicates enabled, treat as DRIFTED.
    any_true = any(_is_true(v) for v in present.values())
    any_false = any((v is False) or (isinstance(v, str) and v.lower() == "false") for v in present.values())

    # If all present properties are False => COMPLIANT; otherwise if any True => DRIFTED.
    state = "DRIFTED" if any_true else "COMPLIANT"

    return {
        "state": state,
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": "Evaluated via Exchange Online (Get-OrganizationConfig candidate properties)",
        "details": details,
    }


def detect_exo_spf_records_all_domains_status(tenant: dict) -> dict:
    """
    Control: EXOSPFRecordsAllDomains (Secure Score: exo_spf_record)

    Fast path:
      - Use Graph to enumerate domains (no EXO connection cost)
      - Then DNS TXT lookup for v=spf1 (bounded, parallel)

    Fallback:
      - If Graph fails or returns no domains, fall back to EXO Get-AcceptedDomain via PS
    """
    # --- Graph-first domain enumeration (fast path) ---
    domains = []
    domain_count = None
    graph_err = None
    data = None

    try:
        import requests

        headers = tenant.get("graphHeaders")
        if not headers:
            raise RuntimeError("Graph headers missing (tenant['graphHeaders'] not set)")

        url = "https://graph.microsoft.com/v1.0/domains?$select=id"
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()

        vals = (r.json() or {}).get("value", []) or []
        domains = [d.get("id") for d in vals if isinstance(d, dict) and isinstance(d.get("id"), str)]
        domain_count = len(domains)

    except Exception as e:
        graph_err = str(e)

    # --- EXO fallback if Graph failed / returned nothing ---
    if not domains:
        ok, data = _run_exo_ps("exo_spf_records_all_domains.ps1", tenant)
        if not ok:
            return _detector_error("exo_spf_records_all_domains.ps1", data)

        domains = (data or {}).get("domains") or []
        domain_count = (data or {}).get("domainCount")

    details = {
        "domainCount": domain_count,
        "domainsReturnedCount": len(domains) if isinstance(domains, list) else 0,
        "domainsTruncated": bool((data or {}).get("domainsTruncated", False)) if isinstance(data, dict) else False,
        "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
        "errors": (data or {}).get("errors") or {},
        "checkedSamples": [],
        "missingSpfCount": None,
        "missingSpfDomains": [],
    }

    # Helpful transparency (does not affect evaluation)
    if graph_err:
        details["graphError"] = graph_err

    missing_keys = []
    if domain_count is None:
        missing_keys.append("domainCount")
    if not isinstance(domains, list):
        missing_keys.append("domains")

    if missing_keys:
        return _missing_data("No domains returned from Graph or EXO", details, missing_keys)

    if len(domains) == 0:
        return _missing_data("No domains returned from Graph or EXO", details, ["domains"])

    from engine.detectors import dns as dns_mod

    if not dns_mod.dnspython_available():
        return _missing_data("dnspython not installed; cannot validate SPF via DNS TXT", details, ["dnspython"])

    checked, missing_domains = dns_mod.bulk_check_spf(
        domains,
        max_workers=10,
        per_domain_timeout_seconds=2.5,
    )

    details["checkedSamples"] = checked[:50]
    details["missingSpfDomains"] = missing_domains
    details["missingSpfCount"] = len(missing_domains)

    state = "DRIFTED" if len(missing_domains) > 0 else "COMPLIANT"
    rd = "Evaluated via Graph domains + DNS TXT lookup for v=spf1 (Python, bounded timeouts)"
    if not tenant.get("graphHeaders"):
        rd = "Evaluated via Exchange Online (Get-AcceptedDomain) + DNS TXT lookup for v=spf1 (Python, bounded timeouts)"

    if state == "DRIFTED":
        rd += f"; {len(missing_domains)} domain(s) missing SPF record or TXT lookup failed/timeout"

    return {
        "state": state,
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": rd,
        "details": details,
    }





def detect_mdo_allowed_senders_restricted_status(tenant: dict) -> dict:
    """
    Control: MDOAllowedSendersRestricted (Secure Score: mdo_allowedsenderscombined)
    Script: mdo_allowed_senders_restricted.ps1

    Intent: AllowedSenders and AllowedSenderDomains should be empty across HostedContentFilterPolicy.
    COMPLIANT: all policies have 0 allowed senders/domains
    DRIFTED: any policy has allow entries
    NOT_EVALUATED: missing data or sampling beyond returned rows
    """
    script = "mdo_allowed_senders_restricted.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details = {
        "policiesCount": count,
        "policies": rows,
        "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
        "errors": (data or {}).get("errors") or {},
    }

    if count is None:
        return _missing_data("EXO did not return policy count", details, ["policiesCount"])

    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys = []
    drift = False
    for r in rows:
        s = r.get("allowedSendersCount")
        d = r.get("allowedDomainsCount")
        if s is None:
            missing_keys.append("AllowedSenders")
        if d is None:
            missing_keys.append("AllowedSenderDomains")
        if (s is not None and int(s) > 0) or (d is not None and int(d) > 0):
            drift = True

    if missing_keys:
        return _missing_data("One or more HostedContentFilterPolicy allowlist properties missing", details, missing_keys)

    state = "DRIFTED" if drift else "COMPLIANT"
    rd = "Evaluated via Exchange Online (Get-HostedContentFilterPolicy allow lists)"
    if drift:
        rd += "; at least one policy contains allowed senders/domains"

    return {"state": state, "reasonCode": "CUSTOM_DETECTOR_EVALUATED", "reasonDetail": rd, "details": details}


def detect_mdo_bulk_complaint_level_threshold_status(tenant: dict) -> dict:
    """
    Control: MDOBulkComplaintLevelThreshold (Secure Score: mdo_bulkcomplaintlevel / mdo_bulkthreshold)
    Script: mdo_bulk_complaint_level_threshold.ps1

    COMPLIANT (recommended): BulkThreshold <= 6 (Standard) AND/OR BulkComplaintLevelThreshold <= 6 when present.
    DRIFTED: any policy has BulkThreshold > 6 or BulkComplaintLevelThreshold > 6
    NOT_EVALUATED: missing required signals or sampling.
    """
    script = "mdo_bulk_complaint_level_threshold.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details = {"policiesCount": count, "policies": rows, "cmdletsUsed": (data or {}).get("cmdletsUsed") or [], "errors": (data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return HostedContentFilterPolicy count", details, ["policiesCount"])

    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys = []
    drift = False

    for r in rows:
        bt = r.get("BulkThreshold")
        bcl = r.get("BulkComplaintLevelThreshold")
        if bt is None and bcl is None:
            missing_keys.append("BulkThreshold/BulkComplaintLevelThreshold")
            continue
        # If present, enforce <= 6
        if bt is not None and int(bt) > 6:
            drift = True
        if bcl is not None and int(bcl) > 6:
            drift = True

    if missing_keys:
        return _missing_data("Bulk threshold signals missing from one or more policies", details, missing_keys)

    state = "DRIFTED" if drift else "COMPLIANT"
    rd = "Evaluated via Exchange Online (Get-HostedContentFilterPolicy bulk thresholds; compliant when <= 6)"

    return {"state": state, "reasonCode": "CUSTOM_DETECTOR_EVALUATED", "reasonDetail": rd, "details": details}


def detect_mdo_bulk_spam_action_status(tenant: dict) -> dict:
    """
    Control: MDOBulkSpamAction (Secure Score: mdo_bulkspamaction)
    Script: mdo_bulk_spam_action.ps1

    COMPLIANT: BulkSpamAction in {MoveToJmf, Quarantine}
    DRIFTED: otherwise
    NOT_EVALUATED: missing required signals or sampling.
    """
    script = "mdo_bulk_spam_action.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details = {"policiesCount": count, "policies": rows, "cmdletsUsed": (data or {}).get("cmdletsUsed") or [], "errors": (data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return HostedContentFilterPolicy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys = []
    drift = False
    for r in rows:
        v = r.get("BulkSpamAction")
        if v is None:
            missing_keys.append("BulkSpamAction")
            continue
        if str(v) not in ("MoveToJmf", "Quarantine"):
            drift = True

    if missing_keys:
        return _missing_data("BulkSpamAction missing from one or more policies", details, missing_keys)

    state = "DRIFTED" if drift else "COMPLIANT"
    rd = "Evaluated via Exchange Online (Get-HostedContentFilterPolicy.BulkSpamAction)"
    return {"state": state, "reasonCode": "CUSTOM_DETECTOR_EVALUATED", "reasonDetail": rd, "details": details}


def detect_mdo_high_confidence_spam_action_status(tenant: dict) -> dict:
    """
    Control: MDOHighConfidenceSpamAction (Secure Score: mdo_highconfidencespamaction)
    Script: mdo_high_confidence_spam_action.ps1

    COMPLIANT: HighConfidenceSpamAction == Quarantine
    DRIFTED: otherwise
    NOT_EVALUATED: missing required signals or sampling.
    """
    script = "mdo_high_confidence_spam_action.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details = {"policiesCount": count, "policies": rows, "cmdletsUsed": (data or {}).get("cmdletsUsed") or [], "errors": (data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return HostedContentFilterPolicy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys = []
    drift = False
    for r in rows:
        v = r.get("HighConfidenceSpamAction")
        if v is None:
            missing_keys.append("HighConfidenceSpamAction")
            continue
        if str(v) != "Quarantine":
            drift = True

    if missing_keys:
        return _missing_data("HighConfidenceSpamAction missing from one or more policies", details, missing_keys)

    state = "DRIFTED" if drift else "COMPLIANT"
    rd = "Evaluated via Exchange Online (Get-HostedContentFilterPolicy.HighConfidenceSpamAction)"
    return {"state": state, "reasonCode": "CUSTOM_DETECTOR_EVALUATED", "reasonDetail": rd, "details": details}


def detect_mdo_phishing_action_status(tenant: dict) -> dict:
    """
    Control: MDOPhishingAction (Secure Score: mdo_highconfidencephishaction / mdo_phisspamacation)
    Script: mdo_phishing_action.ps1

    COMPLIANT: PhishSpamAction == Quarantine (or PhishingAction == Quarantine when present)
    DRIFTED: otherwise
    NOT_EVALUATED: missing required signals or sampling.
    """
    script = "mdo_phishing_action.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details = {"policiesCount": count, "policies": rows, "cmdletsUsed": (data or {}).get("cmdletsUsed") or [], "errors": (data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return HostedContentFilterPolicy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        v1=r.get("PhishSpamAction")
        v2=r.get("PhishingAction")
        v = v1 if v1 is not None else v2
        if v is None:
            missing_keys.append("PhishSpamAction/PhishingAction")
            continue
        if str(v) != "Quarantine":
            drift=True

    if missing_keys:
        return _missing_data("Phishing action missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (Get-HostedContentFilterPolicy phishing action)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_threshold_reached_action_status(tenant: dict) -> dict:
    """
    Control: MDOThresholdReachedAction (Secure Score: mdo_thresholdreachedaction)
    Script: mdo_threshold_reached_action.ps1

    COMPLIANT: ThresholdReachedAction in {MoveToJmf, Quarantine, BlockUser, BlockUserForToday}
    DRIFTED: otherwise
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_threshold_reached_action.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details = {"policiesCount": count, "policies": rows, "cmdletsUsed": (data or {}).get("cmdletsUsed") or [], "errors": (data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    allowed = {"MoveToJmf", "Quarantine", "BlockUser", "BlockUserForToday"}
    missing_keys=[]
    drift=False
    for r in rows:
        v = r.get("ActionWhenThresholdReached")
        if v is None:
            v = r.get("ThresholdReachedAction")
        if v is None:
            missing_keys.append("ThresholdReachedAction")
            continue
        if str(v) not in allowed:
            drift=True

    if missing_keys:
        return _missing_data("ThresholdReachedAction missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (HostedOutboundSpamFilterPolicy action when threshold reached)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_quarantine_retention_period_status(tenant: dict) -> dict:
    """
    Control: MDOQuarantineRetentionPeriod (Secure Score: mdo_quarantineretentionperiod)
    Script: mdo_quarantine_retention_period.ps1

    COMPLIANT (recommended): QuarantineRetentionDays >= 30
    DRIFTED: < 30
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_quarantine_retention_period.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details = {"policiesCount": count, "policies": rows, "cmdletsUsed": (data or {}).get("cmdletsUsed") or [], "errors": (data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        v=r.get("QuarantineRetentionDays")
        if v is None:
            missing_keys.append("QuarantineRetentionDays")
            continue
        if int(v) < 30:
            drift=True

    if missing_keys:
        return _missing_data("QuarantineRetentionDays missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (HostedContentFilterPolicy.QuarantineRetentionDays; compliant when >= 30)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_safe_documents_enabled_status(tenant: dict) -> dict:
    """
    Control: MDOSafeDocumentsEnabled (Secure Score: mdo_safedocuments)
    Script: mdo_safe_documents_enabled.ps1

    COMPLIANT: EnableSafeDocs == True AND EnableSafeDocsForClients == True
    DRIFTED: otherwise
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_safe_documents_enabled.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return Safe Documents policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys = []
    drift = False
    used_fallback = False

    for r in rows:
        # Preferred signal (if tenant exposes it)
        b_raw = r.get("EnableSafeDocsForClients")
        b = _bool(b_raw)

        # Fallback signal (what your tenant actually returns reliably)
        a_raw = r.get("EnableSafeDocs")
        a = _bool(a_raw)

        # Choose signal: primary if present, else fallback
        if b is not None:
            chosen = b
        elif a is not None:
            chosen = a
            used_fallback = True
        else:
            missing_keys.append("EnableSafeDocsForClients/EnableSafeDocs")
            continue

        if not chosen:
            drift = True


    if missing_keys:
        return _missing_data(
            "Safe Documents signals missing from one or more policies",
            details,
            missing_keys,
        )

    state = "DRIFTED" if drift else "COMPLIANT"

    rd = "Evaluated via Exchange Online (Safe Documents policy flags)"
    if used_fallback:
        rd += "; used fallback EnableSafeDocs because EnableSafeDocsForClients was not returned in this tenant"

    return {
        "state": state,
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": rd,
        "details": details,
    }



def detect_mdo_safe_links_office_apps_status(tenant: dict) -> dict:
    """
    Control: MDOSafeLinksOfficeApps (Secure Score: mdo_safelinksforOfficeApps)
    Script: mdo_safe_links_office_apps.ps1

    COMPLIANT: EnableSafeLinksForOffice == True
    DRIFTED: otherwise
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_safe_links_office_apps.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return Safe Links policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        v=_bool(r.get("EnableSafeLinksForOffice"))
        if v is None:
            missing_keys.append("EnableSafeLinksForOffice")
            continue
        if not v:
            drift=True

    if missing_keys:
        return _missing_data("EnableSafeLinksForOffice missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd = "Evaluated via Exchange Online (Safe Links for Office apps policy flags)"


    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_safety_tips_enabled_status(tenant: dict) -> dict:
    """
    Control: MDOSafetyTipsEnabled (Secure Score: similar domains/users/unusual character safety tips)
    Script: mdo_safety_tips_enabled.ps1

    COMPLIANT: EnableSafetyTips (or fallback SafetyTipsEnabled) == True across policies
    DRIFTED: False in any policy
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_safety_tips_enabled.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details = {
        "policiesCount": count,
        "policies": rows,
        "cmdletsUsed": (data or {}).get("cmdletsUsed") or [],
        "errors": (data or {}).get("errors") or {},
    }

    if count is None:
        return _missing_data("EXO did not return AntiPhish policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    # Required safety tips signals (these are the real flags exposed on AntiPhishPolicy in this tenant)
    required = [
        "EnableSimilarUsersSafetyTips",
        "EnableSimilarDomainsSafetyTips",
        "EnableUnusualCharactersSafetyTips",
    ]

    missing_keys = []
    drift = False

    for r in rows:
        for k in required:
            raw = r.get(k)

            # Accept common EXO/PS JSON representations
            if isinstance(raw, bool):
                v = raw
            elif isinstance(raw, (int, float)) and raw in (0, 1):
                v = bool(raw)
            elif isinstance(raw, str) and raw.strip().lower() in ("true", "false"):
                v = raw.strip().lower() == "true"
            else:
                v = None

            if v is None:
                missing_keys.append(k)
            elif not v:
                drift = True

    if missing_keys:
        return _missing_data(
            "Get-AntiPhishPolicy did not return required safety tips flags",
            details,
            missing_keys,
        )

    state = "DRIFTED" if drift else "COMPLIANT"
    rd = "Evaluated via Exchange Online (Get-AntiPhishPolicy safety tips flags: similar users/domains/unusual characters)"

    return {
        "state": state,
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": rd,
        "details": details,
    }



def detect_mdo_spam_notifications_admins_only_status(tenant: dict) -> dict:
    """
    Control: MDOSpamNotificationsAdminsOnly (Secure Score: mdo_spam_notifications_only_for_admins)
    Script: mdo_spam_notifications_admins_only.ps1

    Conservative intent: End-user spam notifications should be disabled (admin-only notification model).
    COMPLIANT: EnableEndUserSpamNotifications == False across policies
    DRIFTED: True in any policy
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_spam_notifications_admins_only.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        v = r.get("EnableEndUserSpamNotifications")
        if v is None:
            missing_keys.append("EnableEndUserSpamNotifications")
            continue
        if _is_true(v):
            drift=True

    if missing_keys:
        return _missing_data("EnableEndUserSpamNotifications is not exposed by Get-HostedContentFilterPolicy in this tenant/module; cannot evaluate without guessing", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (HostedContentFilterPolicy.EnableEndUserSpamNotifications)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_anti_phishing_policies_tuned_status(tenant: dict) -> dict:
    """
    Control: MDOAntiPhishingPoliciesTuned (Secure Score: mdo_antiphishingpolicies)
    Script: mdo_anti_phishing_policies_tuned.ps1

    COMPLIANT: key anti-phish protection toggles are enabled
      - EnableMailboxIntelligence == True
      - EnableMailboxIntelligenceProtection == True
      - EnableTargetedUsersProtection == True
      - EnableTargetedDomainsProtection == True
    DRIFTED: any are False
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_anti_phishing_policies_tuned.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return anti-phishing policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    required = ["EnableMailboxIntelligence","EnableMailboxIntelligenceProtection","EnableTargetedUsersProtection","EnableTargetedDomainsProtection"]
    missing_keys=[]
    drift=False
    for r in rows:
        for k in required:
            v = r.get(k)
            if v is None:
                missing_keys.append(k)
                continue
            if not _is_true(v):
                drift=True

    if missing_keys:
        return _missing_data("Anti-phishing protection signals missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (AntiPhishPolicy core protection toggles)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_block_auto_forwarding_status(tenant: dict) -> dict:
    """
    Control: MDOBlockAutoForwarding (Secure Score: mdo_blockmailforward)
    Script: mdo_block_auto_forwarding.ps1

    COMPLIANT: AutoForwardEnabled == False
    DRIFTED: True
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_block_auto_forwarding.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return transport/config policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        v=r.get("AutoForwardEnabled")
        if v is None:
            missing_keys.append("AutoForwardEnabled")
            continue
        if _is_true(v):
            drift=True

    if missing_keys:
        return _missing_data("AutoForwardEnabled missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (AutoForwardEnabled)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_mailbox_intelligence_actions_configured_status(tenant: dict) -> dict:
    """
    Control: MDOMailboxIntelligenceActionsConfigured (Secure Score: mdo_mailboxintelligenceprotectionaction)
    Script: mdo_mailbox_intelligence_actions_configured.ps1

    COMPLIANT: EnableMailboxIntelligenceProtection == True AND MailboxIntelligenceProtectionAction == Quarantine
    DRIFTED: otherwise
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_mailbox_intelligence_actions_configured.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return anti-phishing policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        en=r.get("EnableMailboxIntelligenceProtection")
        act=r.get("MailboxIntelligenceProtectionAction")
        if en is None:
            missing_keys.append("EnableMailboxIntelligenceProtection")
        elif not _is_true(en):
            drift=True
        if act is None:
            missing_keys.append("MailboxIntelligenceProtectionAction")
        elif str(act) != "Quarantine":
            drift=True

    if missing_keys:
        return _missing_data("Mailbox intelligence action signals missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (AntiPhishPolicy mailbox intelligence protection action)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_mailbox_intelligence_protection_status(tenant: dict) -> dict:
    """
    Control: MDOMailboxIntelligenceProtection (Secure Score: mdo_mailboxintelligenceprotection)
    Script: mdo_mailbox_intelligence_protection.ps1

    COMPLIANT: EnableMailboxIntelligenceProtection == True
    DRIFTED: False
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_mailbox_intelligence_protection.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return anti-phishing policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        v=r.get("EnableMailboxIntelligenceProtection")
        if v is None:
            missing_keys.append("EnableMailboxIntelligenceProtection")
            continue
        if not _is_true(v):
            drift=True

    if missing_keys:
        return _missing_data("EnableMailboxIntelligenceProtection missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (AntiPhishPolicy.EnableMailboxIntelligenceProtection)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_phish_threshold_level_status(tenant: dict) -> dict:
    """
    Control: MDOPhishThresholdLevel (Secure Score: mdo_phishthresholdlevel)
    Script: mdo_phish_threshold_level.ps1

    COMPLIANT (Secure Score-aligned): PhishThresholdLevel >= 2 (Aggressive or higher)
    DRIFTED: < 2
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_phish_threshold_level.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return anti-phishing policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        v=r.get("PhishThresholdLevel")
        if v is None:
            missing_keys.append("PhishThresholdLevel")
            continue
        if int(v) < 2:
            drift=True

    if missing_keys:
        return _missing_data("PhishThresholdLevel missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (AntiPhishPolicy.PhishThresholdLevel; compliant when >= 2)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_targeted_users_protection_status(tenant: dict) -> dict:
    """
    Control: MDOTargetedUsersProtection (Secure Score: mdo_targetedusersprotection)
    Script: mdo_targeted_users_protection.ps1

    COMPLIANT: EnableTargetedUsersProtection == True AND TargetedUsersToProtect not empty
    DRIFTED: otherwise
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_targeted_users_protection.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}

    if count is None:
        return _missing_data("EXO did not return anti-phishing policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        en=r.get("EnableTargetedUsersProtection")
        users=r.get("TargetedUsersToProtect")
        if en is None:
            missing_keys.append("EnableTargetedUsersProtection")
        elif not _is_true(en):
            drift=True

        if users is None:
            missing_keys.append("TargetedUsersToProtect")
        else:
            # users may be list/str
            if isinstance(users, list):
                if len(users) == 0:
                    drift=True
            else:
                if str(users).strip() == "":
                    drift=True

    if missing_keys:
        return _missing_data("Targeted users protection signals missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (AntiPhishPolicy targeted users protection enabled + list populated)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_targeted_domain_protection_status(tenant: dict) -> dict:
    """
    Control: MDOTargetedDomainProtection (Secure Score: mdo_enabledomainstoprotect)
    Script: mdo_targeted_domain_protection.ps1

    COMPLIANT: EnableTargetedDomainsProtection == True AND TargetedDomainsToProtect not empty
    DRIFTED: otherwise
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_targeted_domain_protection.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}
    if count is None:
        return _missing_data("EXO did not return anti-phishing policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        en=r.get("EnableTargetedDomainsProtection")
        dom=r.get("TargetedDomainsToProtect")
        if en is None:
            missing_keys.append("EnableTargetedDomainsProtection")
        elif not _is_true(en):
            drift=True

        if dom is None:
            missing_keys.append("TargetedDomainsToProtect")
        else:
            if isinstance(dom, list):
                if len(dom) == 0:
                    drift=True
            else:
                if str(dom).strip() == "":
                    drift=True

    if missing_keys:
        return _missing_data("Targeted domain protection signals missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (AntiPhishPolicy targeted domains protection enabled + list populated)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_targeted_domain_protection_action_status(tenant: dict) -> dict:
    """
    Control: MDOTargetedDomainProtectionAction (Secure Score: mdo_targeteddomainprotectionaction)
    Script: mdo_targeted_domain_protection_action.ps1

    COMPLIANT: TargetedDomainProtectionAction == Quarantine
    DRIFTED: otherwise
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_targeted_domain_protection_action.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)
    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}
    if count is None:
        return _missing_data("EXO did not return anti-phishing policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        v=r.get("TargetedDomainProtectionAction")
        if v is None:
            missing_keys.append("TargetedDomainProtectionAction")
            continue
        if str(v) != "Quarantine":
            drift=True

    if missing_keys:
        return _missing_data("TargetedDomainProtectionAction missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (AntiPhishPolicy.TargetedDomainProtectionAction)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_targeted_user_protection_action_status(tenant: dict) -> dict:
    """
    Control: MDOTargetedUserProtectionAction (Secure Score: mdo_targeteduserprotectionaction)
    Script: mdo_targeted_user_protection_action.ps1

    COMPLIANT: TargetedUserProtectionAction == Quarantine
    DRIFTED: otherwise
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_targeted_user_protection_action.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)
    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}
    if count is None:
        return _missing_data("EXO did not return anti-phishing policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    missing_keys=[]
    drift=False
    for r in rows:
        v=r.get("TargetedUserProtectionAction")
        if v is None:
            missing_keys.append("TargetedUserProtectionAction")
            continue
        if str(v) != "Quarantine":
            drift=True

    if missing_keys:
        return _missing_data("TargetedUserProtectionAction missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd="Evaluated via Exchange Online (AntiPhishPolicy.TargetedUserProtectionAction)"
    return {"state":state,"reasonCode":"CUSTOM_DETECTOR_EVALUATED","reasonDetail":rd,"details":details}


def detect_mdo_turn_on_mdo_for_spood_teams_status(tenant: dict) -> dict:
    """
    Control: MDOTurnOnMDOForSPOODTeams (Secure Score: mdo_atpprotection)
    Script: mdo_turn_on_mdo_for_spood_teams.ps1

    COMPLIANT: EnableATPForSPOTeamsODB == True (or equivalent per policy)
    DRIFTED: False
    NOT_EVALUATED: missing data or sampling.
    """
    script = "mdo_turn_on_mdo_for_spood_teams.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)

    count, rows = _policy_rows(data)
    details={"policiesCount":count,"policies":rows,"cmdletsUsed":(data or {}).get("cmdletsUsed") or [],"errors":(data or {}).get("errors") or {}}
    if count is None:
        return _missing_data("EXO did not return Safe Attachments policy count", details, ["policiesCount"])
    if _sampled(count, rows):
        return _missing_data("Policy list was truncated in script output; refusing to guess", details, ["policies (full list)"])

    # Property name used in script is expected to be EnableATPForSPOTeamsODB
    missing_keys=[]
    drift=False
    for r in rows:
        v=r.get("EnableATPForSPOTeamsODB")
        if v is None:
            missing_keys.append("EnableATPForSPOTeamsODB")
            continue
        if not _is_true(v):
            drift=True

    if missing_keys:
        return _missing_data("EnableATPForSPOTeamsODB missing from one or more policies", details, missing_keys)

    state="DRIFTED" if drift else "COMPLIANT"
    rd = "Evaluated via Exchange Online (MDO for SharePoint/OneDrive/Teams settings)"

    return {
        "state": state,
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": rd,
        "details": details,
    }



def detect_mdo_bulk_thresholds_snapshot(tenant: dict) -> dict:
    """
    Script-only helper detector (not mapped to a Secure Score control directly):
    Script: mdo_bulk_thresholds.ps1
    Returns COMPLIANT when script succeeds; state is informational only.
    """
    script = "mdo_bulk_thresholds.ps1"
    ok, data = _run_exo_ps(script, tenant)
    if not ok:
        return _detector_error(script, data)
    return {
        "state": "COMPLIANT",
        "reasonCode": "CUSTOM_DETECTOR_EVALUATED",
        "reasonDetail": "Bulk thresholds snapshot collected",
        "details": data or {},
    }
