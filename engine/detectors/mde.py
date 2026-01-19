from typing import Tuple, Dict, Any

def detect_tamper_protection_status() -> Tuple[str, Dict[str, Any]]:
    """
    v1: We may not have MDE API access yet.
    Return a stable signal that Atlas can report now.

    Returns: (state, details)
    """
    # Until MDE API wiring exists, report as DRIFTED with a clear reason.
    # This is still valuable: Atlas is *monitoring* and telling you what's missing.
    return "DRIFTED", {
        "signal": "not_implemented",
        "reason": "MDE tamper protection API not wired yet (detect-only placeholder)",
        "nextStep": "Add MDE API token + query device configuration / security settings",
    }
