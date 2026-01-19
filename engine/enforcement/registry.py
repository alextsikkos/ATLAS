# engine/enforcement/registry.py
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

# Each enforcer returns: (state, reasonCode, reasonDetail, details_dict, http_status_int)
EnforcerFn = Callable[..., tuple[str, str, str, dict, int]]

# Declarative registry: controlId -> enforcer function
ENFORCER_REGISTRY: Dict[str, EnforcerFn] = {}


def register(control_id: str, fn: EnforcerFn) -> None:
    if not control_id or not callable(fn):
        return
    ENFORCER_REGISTRY[control_id] = fn


def get_enforcer(control_id: str) -> Optional[EnforcerFn]:
    return ENFORCER_REGISTRY.get(control_id)
