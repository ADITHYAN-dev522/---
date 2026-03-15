"""
VirusTotal Public API v3 — Hash-based file reputation lookup.

Requires VT_API_KEY environment variable. If not set, all lookups
return a 'skipped' result so the rest of the pipeline still works.
"""

import os
import logging
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15  # seconds per request


def _headers() -> dict:
    return {"x-apikey": VT_API_KEY, "Accept": "application/json"}


def lookup_hash(sha256: str) -> dict:
    """
    Query VirusTotal for a SHA-256 hash.
    Returns structured result regardless of API availability.
    """
    base = {
        "sha256": sha256,
        "queried_at": datetime.utcnow().isoformat(),
        "available": False,
        "positives": 0,
        "total_engines": 0,
        "malware_family": None,
        "threat_label": None,
        "engines_detected": [],
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        "error": None,
    }

    if not VT_API_KEY:
        base["error"] = "VT_API_KEY not set — lookup skipped"
        return base

    url = f"{VT_BASE_URL}/files/{sha256}"
    try:
        resp = requests.get(url, headers=_headers(), timeout=_TIMEOUT)
    except requests.RequestException as exc:
        base["error"] = f"Network error: {exc}"
        return base

    if resp.status_code == 404:
        base["error"] = "Hash not found in VirusTotal database"
        base["available"] = True
        return base

    if resp.status_code == 401:
        base["error"] = "Invalid VT_API_KEY"
        return base

    if resp.status_code == 429:
        base["error"] = "VirusTotal rate limit exceeded (free tier: 4 req/min)"
        return base

    if resp.status_code != 200:
        base["error"] = f"VT API returned HTTP {resp.status_code}"
        return base

    try:
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total     = sum(stats.values())

        engines_detected = [
            {
                "engine": name,
                "verdict": res.get("category"),
                "result": res.get("result"),
            }
            for name, res in results.items()
            if res.get("category") in ("malicious", "suspicious")
        ]

        base.update(
            {
                "available": True,
                "positives": positives,
                "total_engines": total,
                "malware_family": attrs.get("popular_threat_classification", {})
                    .get("suggested_threat_label"),
                "threat_label": attrs.get("meaningful_name"),
                "engines_detected": engines_detected[:20],  # cap to 20
            }
        )
    except Exception as exc:
        base["error"] = f"Response parse error: {exc}"

    return base


def lookup_hashes(sha256_list: list[str]) -> list[dict]:
    """Batch lookup — respects free‑tier rate limit (4 req/min) with simple delay."""
    import time
    results = []
    for i, sha256 in enumerate(sha256_list):
        results.append(lookup_hash(sha256))
        if VT_API_KEY and i < len(sha256_list) - 1:
            time.sleep(15)  # 4 requests/min = 15s apart (free tier)
    return results
