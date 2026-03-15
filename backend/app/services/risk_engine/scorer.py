"""
Risk Scoring Engine — Multi-factor platform risk assessment.

Combines signals from: ClamAV verdict, YARA hits, VirusTotal positives,
and vulnerability severity counts to produce a 0–100 risk score with a
human-readable label.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_DIR  = Path(__file__).resolve().parent.parent.parent.parent
SCANS_DIR = BASE_DIR / "scans"


def _load_json(path: Path) -> dict | list:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def compute_risk_score() -> dict:
    """
    Compute a 0-100 platform risk score from all available scan data.
    Returns dict with: score, label, breakdown, recommendation.
    """
    breakdown: dict[str, int] = {
        "clamav":      0,
        "yara":        0,
        "virustotal":  0,
        "vulnerabilities": 0,
        "wazuh":       0,
    }

    # ── ClamAV ────────────────────────────────────────────────────────────────
    malware_status = _load_json(SCANS_DIR / "malware" / "malware_status.json")
    clamav_infected = malware_status.get("clamav", {}).get("infected_count", 0) if isinstance(malware_status, dict) else 0
    if clamav_infected > 0:
        breakdown["clamav"] = min(35, 15 + clamav_infected * 10)

    # ── YARA ──────────────────────────────────────────────────────────────────
    yara_results = _load_json(SCANS_DIR / "malware" / "yara_results.json")
    if isinstance(yara_results, list):
        yara_hits = sum(len(r.get("matches", [])) for r in yara_results)
        if yara_hits > 0:
            breakdown["yara"] = min(25, yara_hits * 5)

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt_results = _load_json(SCANS_DIR / "malware" / "vt_results.json")
    if isinstance(vt_results, list):
        total_positives = sum(r.get("positives", 0) for r in vt_results if isinstance(r, dict))
        if total_positives > 0:
            breakdown["virustotal"] = min(20, total_positives * 3)

    # ── Vulnerability scan ────────────────────────────────────────────────────
    latest = _load_json(SCANS_DIR / "latest.json")
    crit_count = 0
    high_count = 0
    if isinstance(latest, dict):
        for _dir, scanners in latest.get("results", {}).items():
            if isinstance(scanners, dict):
                trivy = scanners.get("trivy", {})
                for result in (trivy.get("Results", []) if isinstance(trivy, dict) else []):
                    for v in result.get("Vulnerabilities", []):
                        sev = (v.get("Severity") or "").upper()
                        if sev == "CRITICAL": crit_count += 1
                        elif sev == "HIGH":   high_count += 1

    breakdown["vulnerabilities"] = min(15, crit_count * 3 + high_count)

    # ── Wazuh (optional) ──────────────────────────────────────────────────────
    wazuh_alerts = _load_json(SCANS_DIR / "wazuh_alerts.json")
    if isinstance(wazuh_alerts, list) and wazuh_alerts:
        high_sev = [a for a in wazuh_alerts if int(a.get("severity", 0)) >= 7]
        breakdown["wazuh"] = min(5, len(high_sev))

    total_score = sum(breakdown.values())
    total_score = min(100, max(0, total_score))

    # ── Label ─────────────────────────────────────────────────────────────────
    if total_score >= 75:
        label = "CRITICAL"
        color = "#FF1744"
        recommendation = "Immediate action required. Isolate affected systems and begin incident response."
    elif total_score >= 50:
        label = "HIGH"
        color = "#FF6D00"
        recommendation = "High risk detected. Prioritize patching critical vulnerabilities and investigate detections."
    elif total_score >= 25:
        label = "MEDIUM"
        color = "#FFC107"
        recommendation = "Moderate risk. Review open vulnerabilities and monitor system activity."
    else:
        label = "LOW"
        color = "#00E676"
        recommendation = "System appears clean. Maintain regular scanning and patching schedule."

    return {
        "score":          total_score,
        "label":          label,
        "color":          color,
        "recommendation": recommendation,
        "breakdown": {
            "clamav_score":       breakdown["clamav"],
            "yara_score":         breakdown["yara"],
            "virustotal_score":   breakdown["virustotal"],
            "vuln_score":         breakdown["vulnerabilities"],
            "wazuh_score":        breakdown["wazuh"],
            "critical_vulns":     crit_count,
            "high_vulns":         high_count,
            "clamav_infections":  clamav_infected,
        },
    }
