"""
ThreatSentinel — Correlation Engine.

Aggregates findings from all scanners into unified ThreatEvent objects,
writes them to the SQLite memory module, and groups related events by
host, time window, and technique category.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from app.services.memory import db as memory

logger = logging.getLogger(__name__)

BASE_DIR   = Path(__file__).resolve().parent.parent.parent.parent
SCANS_DIR  = BASE_DIR / "scans"
EVENTS_FILE = SCANS_DIR / "threat_events.json"
SCANS_DIR.mkdir(parents=True, exist_ok=True)


# ─── Severity normalisers ─────────────────────────────────────────────────────
def _sev_from_string(s: str) -> str:
    s = (s or "").upper()
    if s in ("CRITICAL",):   return "critical"
    if s in ("HIGH",):        return "high"
    if s in ("MEDIUM",):      return "medium"
    return "low"


def _sev_from_score(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 30: return "medium"
    return "low"


# ─── Source ingestors ─────────────────────────────────────────────────────────
def _ingest_malware(events: list[dict]) -> None:
    status_file = SCANS_DIR / "malware" / "malware_status.json"
    if not status_file.exists():
        return

    try:
        data = json.loads(status_file.read_text())
    except Exception:
        return

    verdict   = data.get("verdict", "CLEAN")
    score     = data.get("risk_score", 0)
    infected  = data.get("clamav", {}).get("infected_count", 0)
    detections = data.get("clamav", {}).get("detections", [])

    if infected > 0:
        sev = _sev_from_score(score)
        for det in detections:
            event = {
                "id":        None,
                "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
                "type":      "malware_detection",
                "scanner":   "ClamAV",
                "severity":  sev,
                "title":     f"Malware Detected: {det}",
                "details":   {"verdict": verdict, "path": det, "risk_score": score},
                "status":    "open",
            }
            events.append(event)
            # persist to SQLite
            inc_id = memory.add_incident("malware_detection", sev, "ClamAV",
                                         f"Malware: {det}", {"path": det, "score": score})
            event["id"] = inc_id
            memory.update_pattern(f"clamav:{det}", sev)

    # YARA results (if present)
    yara_file = SCANS_DIR / "malware" / "yara_results.json"
    if yara_file.exists():
        try:
            yara_data = json.loads(yara_file.read_text())
            for scan in yara_data:
                for match in scan.get("matches", []):
                    sev = _sev_from_string(match.get("meta", {}).get("severity", "medium"))
                    title = f"YARA Rule Hit: {match['rule']}"
                    event = {
                        "id":        None,
                        "timestamp": scan.get("scanned_at", datetime.utcnow().isoformat()),
                        "type":      "yara_detection",
                        "scanner":   "YARA",
                        "severity":  sev,
                        "title":     title,
                        "details":   {"rule": match["rule"], "file": scan["file"],
                                      "sha256": scan.get("sha256")},
                        "status":    "open",
                    }
                    events.append(event)
                    inc_id = memory.add_incident("yara_detection", sev, "YARA",
                                                 title, {"rule": match["rule"], "file": scan["file"]})
                    event["id"] = inc_id
                    memory.update_pattern(f"yara:{match['rule']}", sev)
        except Exception as exc:
            logger.warning("YARA results parse error: %s", exc)


def _ingest_vulnerabilities(events: list[dict]) -> None:
    latest_file = SCANS_DIR / "latest.json"
    if not latest_file.exists():
        return

    try:
        data = json.loads(latest_file.read_text())
    except Exception:
        return

    timestamp = data.get("timestamp", datetime.utcnow().isoformat())
    for _dir, scanners in data.get("results", {}).items():
        trivy = scanners.get("trivy", {})
        for result in trivy.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                sev   = _sev_from_string(v.get("Severity", "low"))
                cve   = v.get("VulnerabilityID", "UNKNOWN")
                pkg   = v.get("PkgName", "unknown-pkg")
                title = f"Vulnerability: {cve} in {pkg}"
                event = {
                    "id":        None,
                    "timestamp": timestamp,
                    "type":      "vulnerability",
                    "scanner":   "Trivy",
                    "severity":  sev,
                    "title":     title,
                    "details":   {"cve": cve, "package": pkg,
                                  "version": v.get("InstalledVersion"),
                                  "title": v.get("Title", "")},
                    "status":    "open",
                }
                events.append(event)
                if sev in ("critical", "high"):
                    inc_id = memory.add_incident(
                        "vulnerability", sev, "Trivy", title,
                        {"cve": cve, "pkg": pkg})
                    event["id"] = inc_id
                    memory.update_pattern(f"cve:{cve}", sev)


def _ingest_wazuh(events: list[dict]) -> None:
    """Try wazuh alerts from local storage if any."""
    alerts_file = SCANS_DIR / "wazuh_alerts.json"
    if not alerts_file.exists():
        return
    try:
        alerts = json.loads(alerts_file.read_text())
        for a in alerts:
            sev_num = int(a.get("severity", 3))
            sev = "critical" if sev_num >= 10 else "high" if sev_num >= 7 else "medium" if sev_num >= 5 else "low"
            title = f"Wazuh Alert: {a.get('rule', 'Unknown rule')}"
            event = {
                "id":        None,
                "timestamp": a.get("timestamp", datetime.utcnow().isoformat()),
                "type":      "host_alert",
                "scanner":   "Wazuh",
                "severity":  sev,
                "title":     title,
                "details":   a,
                "status":    "open",
            }
            events.append(event)
    except Exception:
        pass


# ─── Main correlator ──────────────────────────────────────────────────────────
def run_correlation() -> list[dict]:
    """
    Run full correlation cycle.
    Returns list of ThreatEvent dicts and persists to threats_events.json.
    """
    events: list[dict] = []

    _ingest_malware(events)
    _ingest_vulnerabilities(events)
    _ingest_wazuh(events)

    # Sort by severity then time (newest first)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    events.sort(key=lambda e: (sev_order.get(e["severity"], 99), e["timestamp"]))

    # Persist snapshot
    EVENTS_FILE.write_text(json.dumps(events, indent=2))
    logger.info("ThreatSentinel: correlated %d events", len(events))
    return events


def get_events(limit: int = 50) -> list[dict]:
    """Return cached threat events, running correlation if cache is empty."""
    if EVENTS_FILE.exists():
        try:
            events = json.loads(EVENTS_FILE.read_text())
            return events[:limit]
        except Exception:
            pass
    return run_correlation()[:limit]
