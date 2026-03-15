import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path("scans/threat_intel")
BASE_DIR.mkdir(parents=True, exist_ok=True)

def store(alerts):
    path = BASE_DIR / f"wazuh-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    with open(path, "w") as f:
        json.dump(alerts, f, indent=2)
    return str(path)
