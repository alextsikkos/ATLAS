# Enforcer modules that self-register should be imported here.
# Keep this list limited to enforceable controls only.

# Load the registry so ENFORCER_REGISTRY exists.
import engine.enforcement.registry  # noqa: F401

# Explicitly load new enforcer modules (avoid silent import failures).
import engine.enforcement.auth_methods_policy_enforcers  # noqa: F401
import engine.enforcement.authorization_policy_enforcers  # noqa: F401
