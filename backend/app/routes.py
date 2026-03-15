from fastapi import APIRouter, HTTPException, Query
import subprocess
import json
from pathlib import Path
from pydantic import BaseModel

# ── Safe service imports (wrapped so that missing deps don't crash routes) ──
try:
    from app.services.threat_sentinel import correlator as ts
    _ts_ok = True
except Exception as e:
    print(f"[!] threat_sentinel import failed: {e}")
    _ts_ok = False

try:
    from app.services.memory import db as memory
    _mem_ok = True
except Exception as e:
    print(f"[!] memory import failed: {e}")
    _mem_ok = False

try:
    from app.services.risk_engine import scorer
    _risk_ok = True
except Exception as e:
    print(f"[!] risk_engine import failed: {e}")
    _risk_ok = False

try:
    from app.services.patchmaster import advisor
    _patch_ok = True
except Exception as e:
    print(f"[!] patchmaster import failed: {e}")
    _patch_ok = False

try:
    from app.services.threat_intelligence.wazuh.indexer_client import fetch_alerts
    from app.services.threat_intelligence.wazuh.normalizer import normalize
    _wazuh_ok = True
except Exception as e:
    print(f"[!] wazuh import failed: {e}")
    _wazuh_ok = False

router = APIRouter()

# ==========================================================
# BASE PATHS
# ==========================================================
BASE_DIR          = Path(__file__).resolve().parent.parent
SCANS_DIR         = BASE_DIR / "scans"
MALWARE_STATUS_PATH = SCANS_DIR / "malware" / "malware_status.json"
MALWARE_HISTORY_DIR = SCANS_DIR / "malware" / "scheduled"
TELEMETRY_DIR       = SCANS_DIR / "telemetry"
YARA_RESULTS_PATH   = SCANS_DIR / "malware" / "yara_results.json"
VT_RESULTS_PATH     = SCANS_DIR / "malware" / "vt_results.json"


# ==========================================================
# HEALTH CHECK
# ==========================================================
@router.get("/health")
def health_check():
    return {"status": "backend running"}


# ==========================================================
# VULNERABILITY SCANNERS (on-demand)
# ==========================================================
@router.get("/scan/osv")
def scan_osv(target_path: str = Query(...)):
    try:
        result = subprocess.run(
            ["osv-scanner", "--format=json", "--recursive", target_path],
            capture_output=True, text=True
        )
        if result.returncode not in [0, 1]:
            raise HTTPException(500, result.stderr)
        return json.loads(result.stdout)
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/scan/trivy")
def scan_trivy(target_path: str = Query(...)):
    try:
        result = subprocess.run(
            ["trivy", "fs", "--security-checks", "vuln", "--format", "json", target_path],
            capture_output=True, text=True
        )
        if result.returncode not in [0, 1]:
            raise HTTPException(500, result.stderr)
        return json.loads(result.stdout)
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/scan/semgrep")
def scan_semgrep(target_path: str = Query(...)):
    try:
        result = subprocess.run(
            ["semgrep", "--config", "p/ci", "--json", target_path],
            capture_output=True, text=True
        )
        if result.returncode not in [0, 1]:
            raise HTTPException(500, result.stderr)
        return json.loads(result.stdout)
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/scan/results")
def get_scan_results():
    latest = SCANS_DIR / "latest.json"
    if not latest.exists():
        return {"error": "No scan results yet"}
    try:
        return json.loads(latest.read_text())
    except Exception:
        raise HTTPException(500, "Could not read scan results")


# ==========================================================
# MALWARE — ClamAV status + history
# ==========================================================
def load_malware_status() -> dict | None:
    if not MALWARE_STATUS_PATH.exists():
        return None
    try:
        return json.loads(MALWARE_STATUS_PATH.read_text())
    except Exception:
        return None


@router.get("/malware/status")
def get_malware_status():
    data = load_malware_status()
    if not data:
        raise HTTPException(404, "No malware scan data available")
    return data


@router.get("/malware/history")
def get_malware_history(limit: int = 10):
    if not MALWARE_HISTORY_DIR.exists():
        return []
    files = sorted(
        [f for f in MALWARE_HISTORY_DIR.iterdir() if f.name.startswith("scan-")],
        reverse=True
    )[:limit]
    history = []
    for f in files:
        try:
            history.append(json.loads(f.read_text()))
        except Exception:
            continue
    return history


# ==========================================================
# MALWARE — YARA results
# ==========================================================
@router.get("/malware/yara-results")
def get_yara_results():
    if not YARA_RESULTS_PATH.exists():
        return []
    try:
        return json.loads(YARA_RESULTS_PATH.read_text())
    except Exception:
        raise HTTPException(500, "Could not read YARA results")


# ==========================================================
# MALWARE — VirusTotal results
# ==========================================================
@router.get("/malware/vt-results")
def get_vt_results():
    if not VT_RESULTS_PATH.exists():
        return []
    try:
        return json.loads(VT_RESULTS_PATH.read_text())
    except Exception:
        raise HTTPException(500, "Could not read VT results")


# ==========================================================
# TELEMETRY
# ==========================================================
@router.get("/telemetry/latest")
def get_latest_telemetry():
    if not TELEMETRY_DIR.exists():
        raise HTTPException(404, "Telemetry directory not found")
    files = sorted(
        [f for f in TELEMETRY_DIR.iterdir() if f.name.startswith("telemetry-")],
        reverse=True
    )
    if not files:
        raise HTTPException(404, "No telemetry data available")
    try:
        return json.loads(files[0].read_text())
    except Exception:
        raise HTTPException(500, "Could not read telemetry data")


@router.get("/telemetry/history")
def get_telemetry_history(limit: int = 5):
    if not TELEMETRY_DIR.exists():
        return []
    files = sorted(
        [f for f in TELEMETRY_DIR.iterdir() if f.name.startswith("telemetry-")],
        reverse=True
    )[:limit]
    history = []
    for f in files:
        try:
            history.append(json.loads(f.read_text()))
        except Exception:
            continue
    return history


# ==========================================================
# THREAT SENTINEL — Correlated events
# ==========================================================
@router.get("/threat-sentinel/events")
def get_threat_events(limit: int = 50):
    if not _ts_ok:
        return []
    return ts.get_events(limit=limit)

@router.post("/threat-sentinel/correlate")
def trigger_correlation():
    if not _ts_ok:
        return {"correlated": 0, "events": [], "error": "ThreatSentinel service unavailable"}
    events = ts.run_correlation()
    return {"correlated": len(events), "events": events[:10]}


# ==========================================================
# MEMORY MODULE — Incidents
# ==========================================================
@router.get("/memory/incidents")
def list_incidents(
    status:   str | None = Query(None),
    severity: str | None = Query(None),
    limit:    int        = Query(100),
):
    if not _mem_ok:
        return []
    return memory.get_incidents(status=status, severity=severity, limit=limit)

@router.get("/memory/stats")
def incident_stats():
    if not _mem_ok:
        return {"total_incidents": 0, "open": 0, "resolved": 0, "error": "Memory service unavailable"}
    return memory.get_stats()

class ResolveRequest(BaseModel):
    pass

@router.patch("/memory/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str):
    if not _mem_ok:
        raise HTTPException(503, "Memory service unavailable")
    ok = memory.resolve_incident(incident_id)
    if not ok:
        raise HTTPException(404, f"Incident {incident_id} not found or already resolved")
    return {"resolved": incident_id}


# ==========================================================
# RISK SCORING ENGINE
# ==========================================================
@router.get("/risk/score")
def get_risk_score():
    if not _risk_ok:
        return {
            "score": 0,
            "label": "UNKNOWN",
            "color": "#9E9E9E",
            "recommendation": "Risk engine unavailable. Run scans to compute risk.",
            "breakdown": {},
        }
    return scorer.compute_risk_score()


# ==========================================================
# PATCHMASTER — Remediation recommendations
# ==========================================================
@router.get("/patchmaster/recommendations")
def get_recommendations(limit: int = 50):
    if not _patch_ok:
        return []
    return advisor.get_recommendations(limit=limit)


# ==========================================================
# BASIC COPILOT CHAT (keyword-based fallback, no LLM)
# ==========================================================
class ChatRequest(BaseModel):
    message: str


@router.post("/chat")
def chat(request: ChatRequest):
    latest_file = SCANS_DIR / "latest.json"
    scan_data: dict = {}
    if latest_file.exists():
        try:
            scan_data = json.loads(latest_file.read_text())
        except Exception:
            pass

    user_msg = request.message.lower()
    response = "Security posture summary:\n\n"

    results = scan_data.get("results") or {}
    critical = high = assets = 0
    for _, scanners in results.items():
        trivy = scanners.get("trivy", {})
        for r in trivy.get("Results", []):
            assets += 1
            for v in r.get("Vulnerabilities", []):
                sev = (v.get("Severity") or "").upper()
                if sev == "CRITICAL": critical += 1
                elif sev == "HIGH":   high += 1

    response += f"Critical vulns: {critical}\nHigh vulns: {high}\nAssets scanned: {assets}\n"

    if any(k in user_msg for k in ["malware", "virus", "trojan", "ransom", "yara", "clamav"]):
        malware = load_malware_status()
        if malware:
            response += (
                f"\nMalware Assessment:\n"
                f"Verdict: {malware.get('verdict', 'UNKNOWN')}\n"
                f"Risk Score: {malware.get('risk_score', 0)}\n"
                f"ClamAV Infections: {malware.get('clamav', {}).get('infected_count', 0)}\n"
                f"YARA Hits: {malware.get('yara_hits', 0)}\n"
                f"VirusTotal Positives: {malware.get('vt_positives', 0)}\n"
            )

    return {"response": response}


# ==========================================================
# WAZUH THREAT INTELLIGENCE
# ==========================================================
@router.get("/threat-intel/wazuh/alerts")
def wazuh_alerts(limit: int = 20):
    if not _wazuh_ok:
        return []
    try:
        data = fetch_alerts(limit)
        hits = data.get("hits", {}).get("hits", [])
        return [normalize(h) for h in hits]
    except Exception as e:
        return []
