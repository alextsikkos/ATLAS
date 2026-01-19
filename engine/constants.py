# engine/constants.py

class ControlState:
    COMPLIANT = "COMPLIANT"
    UPDATED = "UPDATED"
    CREATED = "CREATED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED_NOT_IMPLEMENTED = "APPROVED_NOT_IMPLEMENTED"
    NOT_EVALUATED = "NOT_EVALUATED"
    DRIFTED = "DRIFTED"
    ERROR = "ERROR"

# IMPORTANT: mapping must be defined AFTER the class
ACTION_TO_STATE = {
    "ensure_skipped_no_drift": ControlState.COMPLIANT,
    "ensure_updated": ControlState.UPDATED,
    "ensure_created": ControlState.CREATED,
    "detect_only": ControlState.DRIFTED,

    "ensure_skipped_awaiting_approval": ControlState.AWAITING_APPROVAL,
    "ensure_skipped_no_handler": ControlState.APPROVED_NOT_IMPLEMENTED,

    "error": ControlState.ERROR,
}
