import requests
import urllib3

urllib3.disable_warnings()

INDEXER_URL = "https://localhost:9200"
USERNAME = "admin"
PASSWORD = "tME2dI1XLGayCyTj*.um9Mv7ht3i5WF7"

def fetch_alerts(limit=20):
    query = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    r = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-4.x-*/_search",
        auth=(USERNAME, PASSWORD),
        json=query,
        verify=False,
        timeout=10
    )
    r.raise_for_status()
    return r.json()
