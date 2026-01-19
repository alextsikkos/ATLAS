# engine/enforcement/__init__.py
# Import modules that register enforcers into the registry.
# Additive; safe if modules are missing during partial deployments.

try:
    from engine.enforcement import graph_singletons  # noqa: F401
except Exception:
    pass

try:
    from engine.enforcement import ca_enforcers  # noqa: F401
except Exception:
    pass
try:
    from engine.enforcement import authorization_policy_enforcers  # noqa: F401
except Exception:
    pass
try:
    from engine.enforcement import sspr_enforcer  # noqa: F401
except Exception:
    pass
try:
    from engine.enforcement import spo_prevent_reshare_enforcer  # noqa: F401
except Exception:
    pass
# SPO batch tenant-settings enforcer (registers multiple SPO controls; may override single-control enforcer).
try:
    from engine.enforcement import spo_bulk_tenant_settings_enforcer  # noqa: F401
except Exception:
    pass
