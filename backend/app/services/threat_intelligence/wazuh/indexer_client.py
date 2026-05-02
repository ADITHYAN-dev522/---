import requests
import urllib3
import os

urllib3.disable_warnings()

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
USERNAME    = os.getenv("WAZUH_INDEXER_USER", "admin")
PASSWORD    = os.getenv("WAZUH_INDEXER_PASSWORD", "")


def fetch_alerts(limit: int = 20) -> dict:
    if not PASSWORD:
        raise RuntimeError(
            "WAZUH_INDEXER_PASSWORD env var is not set. "
            "Add it to backend/.env or export it in your shell."
        )

    query = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }

    r = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-4.x-*/_search",
        auth=(USERNAME, PASSWORD),
        json=query,
        verify=False,
        timeout=10,
    )
    r.raise_for_status()
    return r.json()
