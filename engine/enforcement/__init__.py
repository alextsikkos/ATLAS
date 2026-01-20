# Enforcer modules that self-register should be imported here.
# Keep this list limited to enforceable controls only.

# Import the registry so that ENFORCER_REGISTRY is populated via import side-effects.
# main.py imports engine.enforcement expecting this wiring.
import engine.enforcement.registry  # noqa: F401