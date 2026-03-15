# app/services/asset_inventory/asset_tags.py

import json
from pathlib import Path

ASSET_TAGS_FILE = Path(__file__).parent / "asset_tags.json"

def load_asset_tags():
    if ASSET_TAGS_FILE.exists():
        try:
            with open(ASSET_TAGS_FILE) as f:
                return json.load(f)
        except Exception:
            pass

    # Default fallback
    return {
        "criticality": "unknown",   # low | medium | high | critical
        "role": "unknown",
        "owner": "unknown"
    }
