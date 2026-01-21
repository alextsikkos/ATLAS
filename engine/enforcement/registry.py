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
    # Load enforcers that register via import side-effects.
    # Keep this additive and best-effort; enforcement must never fail due to import wiring.
    def _safe_import(mod: str) -> None:
        try:
            __import__(mod)
        except Exception as e:
            print(f"[WARN] Failed to import enforcer module {mod}: {type(e).__name__}: {e}")

    # Load enforcers that register via import side-effects.
    # Keep this additive and best-effort; enforcement must never fail due to import wiring.
    _safe_import("engine.enforcement.authorization_policy_bulk")
    _safe_import("engine.enforcement.sspr_enforcer")
    _safe_import("engine.enforcement.auth_methods_policy_enforcers")
    _safe_import("engine.enforcement.authorization_policy_bulk")


    try:
        import engine.enforcement.sspr_enforcer  # noqa: F401
    except Exception:
        pass

    try:
        import engine.enforcement.auth_methods_policy_enforcers  # noqa: F401
    except Exception:
        pass
