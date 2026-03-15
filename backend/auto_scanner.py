"""
auto_scanner.py — Unified scan scheduler for SentinelNexus.

Runs the following pipelines on schedule and at startup:
  1. Vulnerability scan  (OSV + Trivy + Semgrep)  every 2 hours
  2. Malware scan        (ClamAV + YARA + VirusTotal)  every 2h 15m
  3. Telemetry snapshot  (host, processes, network, etc.)  every 1 hour
  4. ThreatSentinel correlation  (after each scan cycle)
"""

import subprocess
import json
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ─── Telemetry imports ────────────────────────────────────────────────────────
from app.services.asset_inventory.host_info import collect_host_info
from app.services.asset_inventory.asset_tags import load_asset_tags
from app.services.telemetry.services import collect_services
from app.services.telemetry.software import collect_installed_software
from app.services.telemetry.processes import collect_processes
from app.services.telemetry.files import collect_recent_files
from app.services.telemetry.network import collect_network_connections

# ─── New service imports ───────────────────────────────────────────────────────
from app.services.yara_engine import scanner as yara_scanner
from app.services.virustotal import lookup as vt_lookup
from app.services.threat_sentinel import correlator as threat_sentinel

# ─── Base paths ───────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).resolve().parent
SCANS_DIR = BASE_DIR / "scans"

TELEMETRY_DIR     = SCANS_DIR / "telemetry"
MALWARE_DIR       = SCANS_DIR / "malware"
MALWARE_SCHEDULED = MALWARE_DIR / "scheduled"

for d in (TELEMETRY_DIR, MALWARE_DIR, MALWARE_SCHEDULED):
    d.mkdir(parents=True, exist_ok=True)

# ─── Scan targets ─────────────────────────────────────────────────────────────
SCAN_DIRS = ["/home/kali/Music"]
MALWARE_SCAN_DIRS = ["/home/kali/Music"]

SAVE_PATH   = SCANS_DIR / "latest.json"
HISTORY_DIR = SCANS_DIR / "history"
HISTORY_DIR.mkdir(parents=True, exist_ok=True)

MALWARE_STATUS_FILE = MALWARE_DIR / "malware_status.json"
YARA_RESULTS_FILE   = MALWARE_DIR / "yara_results.json"
VT_RESULTS_FILE     = MALWARE_DIR / "vt_results.json"


# =========================================================
# SAFE COMMAND EXECUTION
# =========================================================
def safe_run(command: list[str]) -> dict:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if not result.stdout:
            return {"error": "Empty output", "stderr": result.stderr}
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON", "raw": result.stdout[:500]}
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out"}
    except Exception as e:
        return {"error": f"Execution failed: {str(e)}"}


# =========================================================
# VULNERABILITY SCANNERS
# =========================================================
def run_osv(path: str) -> dict:
    return safe_run(["osv-scanner", "--format=json", "--recursive", path])

def run_trivy(path: str) -> dict:
    return safe_run(["trivy", "fs", "--format", "json", "--scanners", "vuln", path])

def run_semgrep(path: str) -> dict:
    return safe_run(["semgrep", "--json", "--config=p/ci", path])

def scan_directory(directory: str) -> dict:
    with ThreadPoolExecutor(max_workers=3) as ex:
        return {
            "osv":    ex.submit(run_osv, directory).result(),
            "trivy":  ex.submit(run_trivy, directory).result(),
            "semgrep": ex.submit(run_semgrep, directory).result(),
        }

def run_all_scans() -> dict:
    print(f"\n[{datetime.now()}] Starting vulnerability scan...")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    results = {"timestamp": timestamp, "directories": SCAN_DIRS, "results": {}}

    with ThreadPoolExecutor(max_workers=len(SCAN_DIRS)) as ex:
        future_map = {ex.submit(scan_directory, d): d for d in SCAN_DIRS}
        for future, directory in future_map.items():
            results["results"][directory] = future.result()

    SAVE_PATH.write_text(json.dumps(results, indent=2))
    (HISTORY_DIR / f"scan-{timestamp}.json").write_text(json.dumps(results, indent=2))
    print("[+] Vulnerability scan saved.")
    return results


# =========================================================
# PHASE-1 TELEMETRY SNAPSHOT
# =========================================================
def run_telemetry_snapshot() -> dict:
    print(f"\n[{datetime.now()}] Starting telemetry snapshot...")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    data = {
        "timestamp":          timestamp,
        "asset":              collect_host_info(),
        "tags":               load_asset_tags(),
        "services":           collect_services(),
        "installed_software": collect_installed_software(),
        "processes":          collect_processes(),
        "recent_files":       collect_recent_files(),
        "network_connections": collect_network_connections(),
    }
    out = TELEMETRY_DIR / f"telemetry-{timestamp}.json"
    out.write_text(json.dumps(data, indent=2))
    print(f"[+] Telemetry saved: {out}")
    return data


# =========================================================
# MALWARE SCANNER — ClamAV
# =========================================================
def run_clamav_scan() -> dict:
    detections: list[str] = []
    for path in MALWARE_SCAN_DIRS:
        cmd = ["clamscan", "-r", "--infected", "--no-summary", path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.endswith("FOUND"):
                detections.append(line.replace(" FOUND", ""))
    return {
        "scanned_paths": MALWARE_SCAN_DIRS,
        "infected_count": len(detections),
        "detections": detections,
    }

def run_auditd_scan() -> str:
    try:
        result = subprocess.run(
            ["ausearch", "-m", "EXECVE", "--format", "json"],
            capture_output=True, text=True
        )
        return result.stdout
    except Exception:
        return ""


# =========================================================
# YARA SCANNING (Phase 2)
# =========================================================
def run_yara_scan() -> list[dict]:
    """Scan each malware scan directory with YARA engine."""
    all_results: list[dict] = []
    for path in MALWARE_SCAN_DIRS:
        results = yara_scanner.scan_directory(path)
        all_results.extend(results)
    YARA_RESULTS_FILE.write_text(json.dumps(all_results, indent=2))
    yara_hits = sum(len(r.get("matches", [])) for r in all_results)
    print(f"[+] YARA scan complete: {yara_hits} rule hits across {len(all_results)} files.")
    return all_results


# =========================================================
# VIRUSTOTAL LOOKUP (Phase 2)
# =========================================================
def run_vt_lookups(yara_results: list[dict]) -> list[dict]:
    """
    For every file that had YARA hits or ClamAV detections,
    compute SHA-256 and look up on VirusTotal.
    """
    hashes: list[str] = []
    for r in yara_results:
        sha256 = r.get("sha256")
        if sha256 and sha256 not in hashes:
            hashes.append(sha256)

    if not hashes:
        VT_RESULTS_FILE.write_text("[]")
        return []

    print(f"[+] Running VirusTotal lookups for {len(hashes)} hashes...")
    vt_results = vt_lookup.lookup_hashes(hashes)
    VT_RESULTS_FILE.write_text(json.dumps(vt_results, indent=2))
    hits = [r for r in vt_results if r.get("positives", 0) > 0]
    print(f"[+] VirusTotal: {len(hits)}/{len(hashes)} hashes flagged by AV engines.")
    return vt_results


# =========================================================
# MALWARE SCORING
# =========================================================
def malware_score(data: dict) -> tuple[int, str]:
    score = 0
    clamav_hits = data["clamav"]["infected_count"]
    yara_hits   = data.get("yara_hits", 0)
    vt_positives = data.get("vt_positives", 0)

    if clamav_hits > 0:  score += 40
    if yara_hits > 0:    score += min(30, yara_hits * 5)
    if vt_positives > 0: score += min(30, vt_positives * 3)

    if score >= 80:   verdict = "CONFIRMED INFECTION"
    elif score >= 40: verdict = "LIKELY COMPROMISE"
    else:             verdict = "CLEAN"
    return score, verdict


def generate_recommendations(data: dict) -> list[dict]:
    infected  = data["clamav"]["infected_count"]
    yara_hits = data.get("yara_hits", 0)
    vt_positive = data.get("vt_positives", 0)

    if infected == 0 and yara_hits == 0 and vt_positive == 0:
        return [
            {"level": "info", "category": "status",     "message": "No malware detected. System appears clean."},
            {"level": "info", "category": "hygiene",    "message": "Ensure antivirus definitions remain up to date."},
            {"level": "info", "category": "monitoring", "message": "Continue periodic malware scans and monitoring."},
        ]

    recs = [
        {"level": "critical", "category": "containment",  "message": "Isolate the affected system from the network immediately."},
        {"level": "high",     "category": "eradication",  "message": "Remove infected files using trusted antivirus tools."},
    ]
    if yara_hits > 0:
        recs.append({"level": "high", "category": "forensics",
                     "message": f"YARA detected {yara_hits} suspicious rule matches — review flagged files manually."})
    if vt_positive > 0:
        recs.append({"level": "critical", "category": "threat-intel",
                     "message": f"VirusTotal flagged {vt_positive} engine detections — malware family confirmed."})
    recs.append({"level": "medium", "category": "hardening",
                 "message": "Review startup services and scheduled tasks for persistence mechanisms."})
    return recs


# =========================================================
# FULL MALWARE PIPELINE (Phase 2)
# =========================================================
def run_malware_scan() -> dict:
    print(f"\n[{datetime.now()}] Starting full malware scan pipeline...")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Step 1: ClamAV
    clamav_data = run_clamav_scan()
    # Step 2: Auditd
    auditd_data = run_auditd_scan()
    # Step 3: YARA
    yara_results = run_yara_scan()
    yara_hits = sum(len(r.get("matches", [])) for r in yara_results)
    # Step 4: VirusTotal for files with YARA hits
    vt_results = run_vt_lookups(yara_results)
    vt_positives = sum(r.get("positives", 0) for r in vt_results)

    data = {
        "timestamp":   timestamp,
        "clamav":      clamav_data,
        "auditd":      auditd_data,
        "yara_hits":   yara_hits,
        "vt_positives": vt_positives,
    }
    score, verdict = malware_score(data)
    data["risk_score"]          = score
    data["verdict"]             = verdict
    data["recommended_actions"] = generate_recommendations(data)

    MALWARE_STATUS_FILE.write_text(json.dumps(data, indent=2))
    (MALWARE_SCHEDULED / f"scan-{timestamp}.json").write_text(json.dumps(data, indent=2))
    print(f"[+] Malware pipeline complete. Verdict: {verdict} | Risk: {score}")
    return data


# =========================================================
# CORRELATION — Run after each scan cycle
# =========================================================
def run_correlation() -> None:
    try:
        threat_sentinel.run_correlation()
        print("[+] ThreatSentinel correlation complete.")
    except Exception as e:
        print(f"[!] Correlation error: {e}")


# =========================================================
# SCHEDULER
# =========================================================
def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_all_scans,          "interval", hours=2)
    scheduler.add_job(run_malware_scan,       "interval", hours=2, minutes=15)
    scheduler.add_job(run_telemetry_snapshot, "interval", hours=1)
    scheduler.add_job(run_correlation,        "interval", hours=2, minutes=30)
    scheduler.start()

    # Startup: run all pipelines in background threads
    for target in (run_all_scans, run_malware_scan, run_telemetry_snapshot, run_correlation):
        Thread(target=target, daemon=True).start()

    print("[+] AUTO: vulnerability + malware (ClamAV+YARA+VT) + telemetry + correlation ENABLED")
