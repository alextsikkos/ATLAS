import json
import os
from typing import Tuple, Dict, Any

APPROVALS_ROOT = "approvals"

def approval_path(tenant: str, control_id: str) -> str:
    return os.path.join(APPROVALS_ROOT, tenant, f"{control_id}.json")

def is_control_approved(tenant: str, control_id: str) -> Tuple[bool, str, Dict[str, Any]]:
    path = approval_path(tenant, control_id)

    if not os.path.isfile(path):
        return False, f"missing approval file: {path}", {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, f"invalid approval JSON: {path} ({e})", {}

    if data.get("approved") is True:
        return True, "approved", data

    return False, f"approval file present but not approved: {path}", data
