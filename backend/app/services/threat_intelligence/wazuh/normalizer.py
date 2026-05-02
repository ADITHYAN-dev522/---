def normalize(hit: dict) -> dict:
    """Convert a raw Wazuh Indexer hit into a flat, frontend-friendly dict."""
    src  = hit.get("_source", {})
    rule = src.get("rule", {})
    return {
        "id":        hit.get("_id"),
        "timestamp": src.get("@timestamp"),
        "severity":  rule.get("level"),
        "rule":      rule.get("description"),
        "rule_id":   rule.get("id"),
        "groups":    rule.get("groups", []),
        "agent":     src.get("agent", {}).get("name"),
        "location":  src.get("location"),
        "mitre":     rule.get("mitre", {}),
        "source":    "wazuh",
    }
