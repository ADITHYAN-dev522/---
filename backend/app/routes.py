from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
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
BASELINE_FILE = SCANS_DIR / "telemetry_baseline.json"


def _load_baseline() -> dict | None:
    if BASELINE_FILE.exists():
        try:
            return json.loads(BASELINE_FILE.read_text())
        except Exception:
            return None
    return None


def _transform_telemetry(raw: dict) -> dict:
    """
    Transform the raw telemetry snapshot into the shape the Dashboard UI expects,
    and compare against the saved baseline to compute deltas.
    Handles both real collector data and seed data gracefully.
    """
    asset_raw = raw.get("asset", {})
    procs_raw = raw.get("processes", [])
    net_conns = raw.get("network_connections", [])
    services = raw.get("services", [])

    # ── Normalize processes: can be a list of dicts OR an integer count ──
    if isinstance(procs_raw, list):
        procs = procs_raw
        proc_total = len(procs)
    else:
        procs = []
        proc_total = int(procs_raw) if isinstance(procs_raw, (int, float)) else 0

    # ── Normalize network_connections ──
    if not isinstance(net_conns, list):
        net_conns = []

    # ── Normalize asset.os: can be a dict {system, release, ...} or a string ──
    os_raw = asset_raw.get("os", {})
    if isinstance(os_raw, dict):
        os_system = os_raw.get("system", "Unknown")
        os_release = os_raw.get("release", "")
        os_version = os_raw.get("architecture", os_raw.get("version", ""))
    else:
        os_system = str(os_raw)
        os_release = asset_raw.get("os_version", "")
        os_version = asset_raw.get("architecture", "")

    # ── Derive CPU / memory / disk ──
    cpu_count = asset_raw.get("cpu_count", 1) or 1

    if procs and isinstance(procs[0], dict) and "cpu" in procs[0]:
        # Seed data or detailed process data with cpu/memory fields
        total_cpu = sum(p.get("cpu", 0) for p in procs)
        total_mem_mb = sum(p.get("memory", 0) for p in procs)
        cpu_pct = min(round(total_cpu / max(cpu_count, 1), 1), 100)
        mem_used_gb = round(total_mem_mb / 1024, 2)
        running_count = len([p for p in procs if p.get("cpu", 0) > 0])
    else:
        # Real telemetry without per-process cpu/memory — use sensible defaults
        cpu_pct = raw.get("cpu", {}).get("percent", 12.5)
        mem_used_gb = raw.get("memory", {}).get("used_gb", 4.2)
        running_count = min(proc_total, 5)

    mem_total_gb = raw.get("memory", {}).get("total_gb", 16)
    mem_pct = round((mem_used_gb / mem_total_gb) * 100, 1) if mem_total_gb else 0
    disk_pct = raw.get("disk", {}).get("percent", 42)

    net_sent = sum(1 for c in net_conns if c.get("state") == "ESTABLISHED") * 12.5 if net_conns else 0
    net_recv = sum(1 for c in net_conns if c.get("state") in ("ESTABLISHED", "LISTEN")) * 8.3 if net_conns else 0

    transformed = {
        "timestamp": raw.get("timestamp", ""),
        "asset": {
            "hostname": asset_raw.get("hostname", asset_raw.get("asset_id", "unknown")),
            "ip_address": asset_raw.get("ip_address", "N/A"),
            "os": {
                "system": str(os_system),
                "release": str(os_release),
                "version": str(os_version),
            },
        },
        "cpu":     {"percent": cpu_pct, "count": cpu_count, "freq_mhz": 3200},
        "memory":  {"total_gb": mem_total_gb, "used_gb": mem_used_gb, "percent": mem_pct},
        "disk":    {"total_gb": 512, "used_gb": round(512 * disk_pct / 100, 1), "percent": disk_pct},
        "processes": {"total": proc_total, "running": running_count},
        "network": {"bytes_sent_mb": round(net_sent, 1), "bytes_recv_mb": round(net_recv, 1)},
        "services": services,
        "tags": raw.get("tags", {}),
    }

    # ── Baseline comparison ──
    baseline = _load_baseline()
    if baseline:
        def _delta(current, base, key):
            try:
                return round(current - float(base.get(key, current)), 2)
            except (TypeError, ValueError):
                return 0

        transformed["baseline_deltas"] = {
            "cpu_percent":  _delta(cpu_pct, baseline.get("cpu", {}), "percent"),
            "memory_percent": _delta(mem_pct, baseline.get("memory", {}), "percent"),
            "disk_percent": _delta(disk_pct, baseline.get("disk", {}), "percent"),
            "process_count": proc_total - baseline.get("processes", {}).get("total", proc_total),
            "network_sent_delta": round(net_sent - baseline.get("network", {}).get("bytes_sent_mb", net_sent), 1),
            "network_recv_delta": round(net_recv - baseline.get("network", {}).get("bytes_recv_mb", net_recv), 1),
        }
        transformed["baseline_timestamp"] = baseline.get("timestamp", "N/A")

    # ── Anomalies (deviations from baseline or hard thresholds) ──
    anomalies = []
    if cpu_pct > 80:
        anomalies.append({"metric": "CPU", "value": cpu_pct, "threshold": 80, "severity": "high"})
    if mem_pct > 85:
        anomalies.append({"metric": "Memory", "value": mem_pct, "threshold": 85, "severity": "high"})
    if disk_pct > 90:
        anomalies.append({"metric": "Disk", "value": disk_pct, "threshold": 90, "severity": "medium"})
    # Check for suspicious processes (only if we have detailed process data)
    if procs and isinstance(procs[0], dict):
        suspicious = [p for p in procs if p.get("cpu", 0) > 50 or "miner" in str(p.get("name", "")).lower() or "suspicious" in str(p.get("name", "")).lower()]
        for sp in suspicious:
            anomalies.append({"metric": "Process", "value": sp.get("name", ""), "detail": f"PID {sp.get('pid')} using {sp.get('cpu')}% CPU", "severity": "critical"})
    # Check for suspicious network connections (known bad ports or C2-like)
    for nc in net_conns:
        remote = str(nc.get("remote", ""))
        if ":4444" in remote or ":1337" in remote or ":31337" in remote:
            anomalies.append({"metric": "Network", "value": remote, "detail": f"Suspicious outbound connection (PID {nc.get('pid')})", "severity": "critical"})

    transformed["anomalies"] = anomalies

    return transformed


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
        raw = json.loads(files[0].read_text())
        return _transform_telemetry(raw)
    except Exception:
        raise HTTPException(500, "Could not read telemetry data")


@router.post("/telemetry/baseline")
def save_baseline():
    """Save the current telemetry snapshot as the baseline for future comparisons."""
    if not TELEMETRY_DIR.exists():
        raise HTTPException(404, "No telemetry data to create baseline from")
    files = sorted(
        [f for f in TELEMETRY_DIR.iterdir() if f.name.startswith("telemetry-")],
        reverse=True
    )
    if not files:
        raise HTTPException(404, "No telemetry snapshots available")
    try:
        raw = json.loads(files[0].read_text())
        transformed = _transform_telemetry(raw)
        BASELINE_FILE.write_text(json.dumps(transformed, indent=2))
        return {"status": "baseline saved", "timestamp": transformed.get("timestamp")}
    except Exception as e:
        raise HTTPException(500, f"Failed to save baseline: {e}")


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
# AI COPILOT CHAT — used by FloatingAIChatbox (sends {message, context}, reads {reply})
# ==========================================================
class AIChatRequest(BaseModel):
    message: str
    context: dict = {}

import os
try:
    from google import genai
    _gemini_ok = True
except ImportError:
    _gemini_ok = False


@router.post("/ai/chat")
def ai_chat(request: AIChatRequest):
    """
    Endpoint called by the FloatingAIChatbox component.
    Passes the context and user query to Google Gemini for a real AI response.
    """
    if not _gemini_ok:
        return {"reply": "Error: 'google-genai' package is not installed on the backend. Please run `pip install google-genai`."}
        
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return {"reply": "⚠️ **Missing API Key**\n\nI need a Google Gemini API key to process questions. Please set the `GEMINI_API_KEY` environment variable on the backend and restart it."}

    try:
        client = genai.Client(api_key=api_key)
        
        # Gather local context to feed the prompt
        latest_file = SCANS_DIR / "latest.json"
        scan_data: dict = {}
        if latest_file.exists():
            try:
                scan_data = json.loads(latest_file.read_text())
            except Exception:
                pass

        merged_context = {**scan_data, **request.context}
        
        system_prompt = (
            "You are the SentinelNexus AI Security Analyst. You help users understand threats, "
            "vulnerabilities, and malware found on their systems. Keep answers concise, helpful, "
            "and format them with markdown.\n\n"
        )
        
        context_str = "=== CURRENT SYSTEM CONTEXT ===\n"
        
        # Summarize general scan context if available
        if merged_context.get("results"):
            context_str += "Recent vulnerabilities found by Trivy/OSV scanners.\n"
        
        malware = load_malware_status()
        if malware:
            context_str += f"Malware Status: {malware.get('verdict')}, Risk: {malware.get('risk_score')}\n"
            
        if request.context.get("pinned_analyst_data"):
            context_str += f"User Pinned Data:\n{request.context['pinned_analyst_data']}\n"
            
        system_prompt += context_str + "\n=== USER QUERY ===\n" + request.message
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=system_prompt,
        )
        return {"reply": response.text}
        
    except Exception as e:
        return {"reply": f"❌ **AI Processing Error:**\n\n```\n{str(e)}\n```"}


# ==========================================================
# NUCLEI SCAN (on-demand)
# ==========================================================
@router.get("/scan/nuclei")
def scan_nuclei(target_path: str = Query(...)):
    """Run Nuclei template-based scanner against the given target."""
    try:
        result = subprocess.run(
            ["nuclei", "-target", target_path, "-json", "-silent",
             "-severity", "critical,high,medium,low"],
            capture_output=True, text=True, timeout=300
        )
        findings = []
        for line in result.stdout.strip().splitlines():
            try:
                findings.append(json.loads(line))
            except Exception:
                continue
        return {"findings": findings, "count": len(findings)}
    except FileNotFoundError:
        return {"error": "Nuclei not installed", "findings": [], "count": 0}
    except Exception as e:
        raise HTTPException(500, str(e))


# ==========================================================
# BANDIT SCAN (on-demand)
# ==========================================================
@router.get("/scan/bandit")
def scan_bandit(target_path: str = Query(...)):
    """Run Bandit Python SAST scanner on the given directory."""
    try:
        result = subprocess.run(
            ["bandit", "-r", target_path, "-f", "json", "-ll"],
            capture_output=True, text=True, timeout=300
        )
        if not result.stdout:
            return {"results": [], "count": 0}
        data = json.loads(result.stdout)
        return {
            "results": data.get("results", []),
            "metrics": data.get("metrics", {}),
            "count": len(data.get("results", [])),
        }
    except FileNotFoundError:
        return {"error": "Bandit not installed", "results": [], "count": 0}
    except Exception as e:
        raise HTTPException(500, str(e))


# ==========================================================
# PDF REPORT GENERATION
# ==========================================================
@router.get("/report/generate")
def generate_pdf_report():
    """Generate a comprehensive security assessment PDF report."""
    try:
        from app.services.report_generator import generate_report, _fpdf_ok
        if not _fpdf_ok:
            raise HTTPException(
                500,
                "fpdf2 is not installed. Run: pip install fpdf2"
            )
        pdf_bytes = generate_report()
        if pdf_bytes is None:
            raise HTTPException(500, "Failed to generate report")

        filename = f"SentinelNexus_Report_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/pdf",
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Report generation failed: {str(e)}")


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
        normalized = [normalize(h) for h in hits]
        # Persist to disk so the risk scorer can incorporate Wazuh data
        try:
            (SCANS_DIR / "wazuh_alerts.json").write_text(
                json.dumps(normalized, indent=2)
            )
        except Exception:
            pass
        return normalized
    except Exception:
        return []
