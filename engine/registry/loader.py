import json
import os
from typing import Any, Dict, List

REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "controls.json")

def load_controls() -> List[Dict[str, Any]]:
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def build_securescore_to_atlas_map(controls: List[Dict[str, Any]]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for c in controls:
        atlas_id = c.get("id")
        if not atlas_id:
            continue
        for ss_id in c.get("secureScoreControlIds", []) or []:
            mapping[ss_id] = atlas_id
    return mapping
