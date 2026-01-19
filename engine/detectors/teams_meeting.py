# engine/detectors/teams_meeting.py
import json
import subprocess
from pathlib import Path


def run_teams_meeting_policies(tenant_id: str, app_id: str, certificate_thumbprint: str) -> dict:
    """
    Pull meeting policy settings via MicrosoftTeams PowerShell.

    Returns:
      { "ok": True, "policies": [ ... ], "presentKeys": [ ... ] }
    or:
      { "ok": False, "error": "..." }
    """
    script_path = Path(__file__).resolve().parent / "teams_meeting_policies.ps1"

    ps_cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        "-TenantId",
        str(tenant_id),
        "-AppId",
        str(app_id),
        "-CertificateThumbprint",
        str(certificate_thumbprint),
    ]

    proc = subprocess.run(ps_cmd, capture_output=True, text=True)
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()

    if proc.returncode != 0:
        return {"ok": False, "error": err or f"PowerShell exited with {proc.returncode}"}

    try:
        data = json.loads(out) if out else {}
        if not isinstance(data, dict):
            return {"ok": False, "error": "Unexpected Teams meeting detector output (not a JSON object)"}
        if err:
            data["stderr"] = err
        return data
    except Exception as e:
        return {"ok": False, "error": f"Failed to parse Teams meeting detector JSON: {e}", "raw": out, "stderr": err}


def _pick_global_policy(policies: list) -> dict | None:
    if not isinstance(policies, list) or not policies:
        return None
    for p in policies:
        if (p.get("Identity") or "").lower() == "global":
            return p
    return policies[0]


def _missing_keys(policy: dict, keys: list[str]) -> list[str]:
    return [k for k in keys if k not in policy]


def _result_not_evaluated(msg: str, policy: dict | None, meeting_result: dict, missing_keys: list[str] | None = None) -> dict:
    details = {
        "error": msg,
        "policyIdentity": (policy or {}).get("Identity") if isinstance(policy, dict) else None,
        "presentKeys": meeting_result.get("presentKeys"),
    }
    if missing_keys:
        details["missingKeys"] = missing_keys
    return {
        "state": "NOT_EVALUATED",
        "details": details,
        "reasonCode": "MISSING_DATA",
        "reasonDetail": msg,
    }


def _eval_equals(meeting_result: dict, setting_key: str, expected, expected_label: str | None = None) -> dict:
    policies = meeting_result.get("policies")
    policy = _pick_global_policy(policies)

    if not policy:
        return {
            "state": "NOT_EVALUATED",
            "details": {"error": "No meeting policies returned", "raw": meeting_result},
            "reasonCode": "MISSING_DATA",
            "reasonDetail": "No meeting policies returned",
        }

    missing = _missing_keys(policy, [setting_key])
    if missing:
        return _result_not_evaluated(
            "Missing required keys in Teams meeting policy",
            policy=policy,
            meeting_result=meeting_result,
            missing_keys=missing,
        )

    actual = policy.get(setting_key)

    # Conservative compare:
    if isinstance(expected, bool):
        ok = (bool(actual) == expected)
    else:
        ok = (str(actual) == str(expected))

    state = "COMPLIANT" if ok else "DRIFTED"

    return {
        "state": state,
        "details": {
            "policyIdentity": policy.get("Identity"),
            "setting": setting_key,
            "expected": expected if expected_label is None else expected_label,
            "actual": actual,
        },
        "reasonCode": "FALLBACK_DETECTOR_EVALUATED",
        "reasonDetail": "Evaluated via Teams meeting policy (MicrosoftTeams PowerShell)",
    }


def detect_teams_auto_admit_invited_only_status(meeting_result: dict) -> dict:
    # AutoAdmittedUsers must be InvitedUsers
    return _eval_equals(meeting_result, "AutoAdmittedUsers", "InvitedUsers")


def detect_teams_designated_presenter_configured_status(meeting_result: dict) -> dict:
    # DesignatedPresenterRoleMode must be OrganizerOnlyUserOverride
    return _eval_equals(meeting_result, "DesignatedPresenterRoleMode", "OrganizerOnlyUserOverride")


def detect_teams_limit_external_control_status(meeting_result: dict) -> dict:
    # AllowExternalParticipantGiveRequestControl must be False
    return _eval_equals(meeting_result, "AllowExternalParticipantGiveRequestControl", False)


def detect_teams_restrict_anonymous_join_status(meeting_result: dict) -> dict:
    # AllowAnonymousUsersToJoinMeeting must be False
    return _eval_equals(meeting_result, "AllowAnonymousUsersToJoinMeeting", False)


def detect_teams_restrict_anonymous_start_meeting_status(meeting_result: dict) -> dict:
    # AllowAnonymousUsersToStartMeeting must be False
    return _eval_equals(meeting_result, "AllowAnonymousUsersToStartMeeting", False)


def detect_teams_restrict_dialin_bypass_lobby_status(meeting_result: dict) -> dict:
    # AllowPSTNUsersToBypassLobby must be False
    return _eval_equals(meeting_result, "AllowPSTNUsersToBypassLobby", False)
