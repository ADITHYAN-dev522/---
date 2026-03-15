def normalize(hit):
    src = hit.get("_source", {})
    return {
        "timestamp": src.get("@timestamp"),
        "severity": src.get("rule", {}).get("level"),
        "rule": src.get("rule", {}).get("description"),
        "agent": src.get("agent", {}).get("name"),
        "source": "wazuh"
    }
