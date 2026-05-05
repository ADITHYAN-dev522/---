"""
seed_test_data.py - Populates ALL SentinelNexus data stores with realistic test data.

Run:  python seed_test_data.py
"""
import json, sqlite3, uuid
from pathlib import Path
from datetime import datetime, timedelta

BASE = Path(__file__).resolve().parent
SCANS = BASE / "scans"
MALWARE = SCANS / "malware"
TELEMETRY = SCANS / "telemetry"
for d in (SCANS, MALWARE, MALWARE / "scheduled", TELEMETRY):
    d.mkdir(parents=True, exist_ok=True)

NOW = datetime.now()
TS = NOW.strftime("%Y-%m-%d_%H-%M-%S")

# ============================================================
# 1. VULNERABILITY SCAN (latest.json) - Trivy + OSV + Semgrep + Nuclei + Bandit
# ============================================================
latest = {
    "timestamp": TS,
    "directories": ["/home/kali/Music/webapp", "/home/kali/Music/api-server"],
    "results": {
        "/home/kali/Music/webapp": {
            "trivy": {
                "Results": [{
                    "Target": "package-lock.json",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-21888", "Severity": "CRITICAL", "PkgName": "express",
                         "InstalledVersion": "4.17.1", "FixedVersion": "4.19.2",
                         "Title": "Express.js Open Redirect vulnerability", "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-21888"},
                        {"VulnerabilityID": "CVE-2024-29041", "Severity": "CRITICAL", "PkgName": "lodash",
                         "InstalledVersion": "4.17.15", "FixedVersion": "4.17.21",
                         "Title": "Prototype Pollution in lodash", "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-29041"},
                        {"VulnerabilityID": "CVE-2023-44487", "Severity": "HIGH", "PkgName": "node",
                         "InstalledVersion": "18.12.0", "FixedVersion": "18.18.2",
                         "Title": "HTTP/2 Rapid Reset Attack", "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"},
                        {"VulnerabilityID": "CVE-2023-32002", "Severity": "HIGH", "PkgName": "node",
                         "InstalledVersion": "18.12.0", "FixedVersion": "18.17.1",
                         "Title": "Node.js Policy bypass via Module._load", "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-32002"},
                        {"VulnerabilityID": "CVE-2024-22019", "Severity": "MEDIUM", "PkgName": "axios",
                         "InstalledVersion": "0.21.1", "FixedVersion": "1.6.5",
                         "Title": "Server-Side Request Forgery in Axios", "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-22019"},
                    ]
                }]
            },
            "osv": {
                "results": [{
                    "vulns": [
                        {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2023-46233"], "summary": "Crypto-js PBKDF2 1000 iteration default"},
                        {"id": "GHSA-9wv6-86v2-598j", "aliases": ["CVE-2024-28849"], "summary": "follow-redirects exposes credentials"},
                    ]
                }]
            },
            "semgrep": {
                "results": [
                    {"check_id": "javascript.lang.security.audit.sqli", "path": "src/db/query.js",
                     "start": {"line": 42}, "extra": {"severity": "ERROR", "message": "SQL injection via string concatenation"}},
                    {"check_id": "javascript.express.security.audit.xss.mustache-escape",
                     "path": "src/views/profile.ejs", "start": {"line": 18},
                     "extra": {"severity": "WARNING", "message": "Unescaped user input in template"}},
                    {"check_id": "javascript.lang.security.detect-eval", "path": "src/utils/parser.js",
                     "start": {"line": 87}, "extra": {"severity": "ERROR", "message": "Use of eval() detected"}},
                ]
            },
            "nuclei": {
                "findings": [
                    {"template-id": "git-config-exposure", "host": "http://localhost:3000/.git/config",
                     "matched-at": "http://localhost:3000/.git/config",
                     "info": {"name": "Git Config Exposure", "severity": "high", "tags": ["exposure", "git", "config"]}},
                    {"template-id": "env-file-disclosure", "host": "http://localhost:3000/.env",
                     "matched-at": "http://localhost:3000/.env",
                     "info": {"name": ".env File Disclosure", "severity": "medium", "tags": ["exposure", "env"]}},
                ]
            },
            "bandit": {
                "results": [
                    {"test_id": "B301", "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
                     "issue_text": "Pickle usage detected - potential deserialization attack",
                     "filename": "src/cache/serializer.py", "line_number": 23},
                    {"test_id": "B608", "issue_severity": "HIGH", "issue_confidence": "MEDIUM",
                     "issue_text": "Possible SQL injection via string-based query construction",
                     "filename": "src/db/connector.py", "line_number": 55},
                ]
            }
        },
        "/home/kali/Music/api-server": {
            "trivy": {
                "Results": [{
                    "Target": "requirements.txt",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-34062", "Severity": "HIGH", "PkgName": "flask",
                         "InstalledVersion": "2.2.0", "FixedVersion": "2.3.3",
                         "Title": "Flask debugger PIN bypass", "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-34062"},
                        {"VulnerabilityID": "CVE-2024-35195", "Severity": "CRITICAL", "PkgName": "requests",
                         "InstalledVersion": "2.28.0", "FixedVersion": "2.32.0",
                         "Title": "Requests Session credential leak on redirect", "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-35195"},
                        {"VulnerabilityID": "CVE-2023-37920", "Severity": "HIGH", "PkgName": "certifi",
                         "InstalledVersion": "2022.12.7", "FixedVersion": "2023.7.22",
                         "Title": "Certifi removes e-Tugra root certificate", "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-37920"},
                        {"VulnerabilityID": "CVE-2024-3651", "Severity": "MEDIUM", "PkgName": "idna",
                         "InstalledVersion": "3.4", "FixedVersion": "3.7",
                         "Title": "idna excessive resource consumption", "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-3651"},
                    ]
                }]
            },
            "osv": {"results": [{"vulns": [
                {"id": "PYSEC-2024-1001", "aliases": ["CVE-2024-34069"], "summary": "Werkzeug debugger RCE via crafted request"}
            ]}]},
            "semgrep": {"results": [
                {"check_id": "python.flask.security.audit.hardcoded-secret", "path": "app/config.py",
                 "start": {"line": 12}, "extra": {"severity": "ERROR", "message": "Hardcoded SECRET_KEY in Flask config"}},
            ]},
            "nuclei": {"findings": []},
            "bandit": {"results": [
                {"test_id": "B105", "issue_severity": "LOW", "issue_confidence": "MEDIUM",
                 "issue_text": "Possible hardcoded password in variable assignment",
                 "filename": "app/config.py", "line_number": 14},
            ]}
        }
    }
}
(SCANS / "latest.json").write_text(json.dumps(latest, indent=2))
print("[+] Wrote latest.json (Trivy/OSV/Semgrep/Nuclei/Bandit)")

# ============================================================
# 2. MALWARE STATUS (ClamAV)
# ============================================================
malware_status = {
    "timestamp": TS,
    "clamav": {
        "scanned_paths": ["/home/kali/Music/webapp/uploads", "/home/kali/Music/suspicious"],
        "infected_count": 3,
        "detections": [
            "/home/kali/Music/webapp/uploads/invoice.pdf.exe: Win.Trojan.Agent-798345",
            "/home/kali/Music/suspicious/svchost.bin: Trojan.Downloader.Generic",
            "/home/kali/Music/webapp/uploads/readme.scr: Win.Ransomware.Locky-9903455"
        ]
    },
    "auditd": "",
    "yara_hits": 4,
    "vt_positives": 7,
    "risk_score": 85,
    "verdict": "CONFIRMED INFECTION",
    "recommended_actions": [
        {"level": "critical", "category": "containment", "message": "Isolate the affected system from the network immediately."},
        {"level": "high", "category": "eradication", "message": "Remove infected files using trusted antivirus tools."},
        {"level": "high", "category": "forensics", "message": "YARA detected 4 suspicious rule matches - review flagged files manually."},
        {"level": "critical", "category": "threat-intel", "message": "VirusTotal flagged 7 engine detections - malware family confirmed."},
        {"level": "medium", "category": "hardening", "message": "Review startup services and scheduled tasks for persistence mechanisms."}
    ]
}
(MALWARE / "malware_status.json").write_text(json.dumps(malware_status, indent=2))
print("[+] Wrote malware_status.json (ClamAV)")

# ============================================================
# 3. YARA RESULTS
# ============================================================
yara_results = [
    {"file": "/home/kali/Music/webapp/uploads/invoice.pdf.exe",
     "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "md5": "d41d8cd98f00b204e9800998ecf8427e",
     "matches": [
         {"rule": "Suspicious_PowerShell", "namespace": "__builtin__", "tags": [],
          "meta": {"description": "Obfuscated PowerShell invocation", "severity": "high"},
          "strings": [{"identifier": "$enc", "offset": 1024}]},
         {"rule": "Base64_Shellcode", "namespace": "__builtin__", "tags": [],
          "meta": {"description": "Large base64 blob typical of encoded shellcode", "severity": "medium"},
          "strings": [{"identifier": "$b64", "offset": 2048}]}
     ], "error": None, "scanned_at": NOW.isoformat()},
    {"file": "/home/kali/Music/suspicious/svchost.bin",
     "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
     "sha1": "1234567890abcdef1234567890abcdef12345678", "md5": "abcdef1234567890abcdef1234567890",
     "matches": [
         {"rule": "Reverse_Shell_Bash", "namespace": "__builtin__", "tags": [],
          "meta": {"description": "Potential bash reverse shell", "severity": "critical"},
          "strings": [{"identifier": "$rs1", "offset": 512}]}
     ], "error": None, "scanned_at": NOW.isoformat()},
    {"file": "/home/kali/Music/webapp/uploads/readme.scr",
     "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
     "sha1": "aabbccddeeff00112233aabbccddeeff00112233", "md5": "00112233445566778899aabbccddeeff",
     "matches": [
         {"rule": "Mime_Executable_In_Script", "namespace": "__builtin__", "tags": [],
          "meta": {"description": "ELF or PE magic bytes embedded inside a file", "severity": "high"},
          "strings": [{"identifier": "$pe", "offset": 0}]}
     ], "error": None, "scanned_at": NOW.isoformat()},
    {"file": "/home/kali/Music/api-server/app/config.py",
     "sha256": "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
     "sha1": "1111222233334444555566667777888899990000", "md5": "aabbccddeeff0011aabbccddeeff0011",
     "matches": [], "error": None, "scanned_at": NOW.isoformat()},
]
(MALWARE / "yara_results.json").write_text(json.dumps(yara_results, indent=2))
print("[+] Wrote yara_results.json (YARA)")

# ============================================================
# 4. VIRUSTOTAL RESULTS
# ============================================================
vt_results = [
    {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "positives": 3, "total_engines": 72,
     "malware_family": "Trojan.Agent", "threat_label": "trojan.win32/agent",
     "scan_date": NOW.isoformat()},
    {"sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
     "positives": 2, "total_engines": 72,
     "malware_family": "Backdoor.ReverseShell", "threat_label": "backdoor.linux/reverseshell",
     "scan_date": NOW.isoformat()},
    {"sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
     "positives": 2, "total_engines": 72,
     "malware_family": "Ransom.Locky", "threat_label": "ransom.win32/locky",
     "scan_date": NOW.isoformat()},
]
(MALWARE / "vt_results.json").write_text(json.dumps(vt_results, indent=2))
print("[+] Wrote vt_results.json (VirusTotal)")

# ============================================================
# 5. WAZUH ALERTS
# ============================================================
wazuh_alerts = [
    {"severity": 12, "rule": "SSH brute-force attack detected (10+ failed logins)",
     "agent": "web-server-01", "timestamp": (NOW - timedelta(minutes=30)).isoformat(),
     "source_ip": "185.220.101.34", "category": "authentication_failure"},
    {"severity": 10, "rule": "Rootkit detection: suspicious file /usr/bin/.hidden_shell",
     "agent": "web-server-01", "timestamp": (NOW - timedelta(minutes=25)).isoformat(),
     "source_ip": "local", "category": "rootkit"},
    {"severity": 8, "rule": "Privilege escalation attempt: sudo to root from unauthorized user",
     "agent": "db-server-02", "timestamp": (NOW - timedelta(minutes=15)).isoformat(),
     "source_ip": "10.0.0.45", "category": "privilege_escalation"},
    {"severity": 7, "rule": "File integrity monitoring: /etc/passwd modified",
     "agent": "web-server-01", "timestamp": (NOW - timedelta(minutes=10)).isoformat(),
     "source_ip": "local", "category": "file_integrity"},
    {"severity": 5, "rule": "Firewall: outbound connection to known C2 server blocked",
     "agent": "web-server-01", "timestamp": (NOW - timedelta(minutes=5)).isoformat(),
     "source_ip": "10.0.0.12", "category": "network_threat"},
    {"severity": 4, "rule": "Successful SSH login from new IP address",
     "agent": "db-server-02", "timestamp": NOW.isoformat(),
     "source_ip": "203.0.113.55", "category": "authentication"},
]
(SCANS / "wazuh_alerts.json").write_text(json.dumps(wazuh_alerts, indent=2))
print("[+] Wrote wazuh_alerts.json (Wazuh SIEM)")

# ============================================================
# 6. TELEMETRY SNAPSHOT
# ============================================================
import platform, os
telemetry = {
    "timestamp": TS,
    "asset": {
        "hostname": platform.node(), "os": platform.system(), "os_version": platform.version(),
        "architecture": platform.machine(), "cpu_count": os.cpu_count(), "uptime_hours": 172
    },
    "tags": {"environment": "production", "role": "web-server", "criticality": "high"},
    "services": [
        {"name": "nginx", "status": "running", "pid": 1234, "port": 80},
        {"name": "node", "status": "running", "pid": 2345, "port": 3000},
        {"name": "postgresql", "status": "running", "pid": 3456, "port": 5432},
        {"name": "redis", "status": "running", "pid": 4567, "port": 6379},
        {"name": "sshd", "status": "running", "pid": 892, "port": 22},
    ],
    "installed_software": [
        {"name": "Node.js", "version": "18.12.0"}, {"name": "Python", "version": "3.11.4"},
        {"name": "PostgreSQL", "version": "15.3"}, {"name": "Nginx", "version": "1.24.0"},
    ],
    "processes": [
        {"pid": 1234, "name": "nginx", "cpu": 2.1, "memory": 45.2},
        {"pid": 2345, "name": "node", "cpu": 15.3, "memory": 312.5},
        {"pid": 9999, "name": "suspicious_miner.bin", "cpu": 89.2, "memory": 1024.0},
    ],
    "recent_files": [
        {"path": "/home/kali/Music/webapp/uploads/invoice.pdf.exe", "modified": (NOW - timedelta(hours=1)).isoformat()},
        {"path": "/home/kali/Music/suspicious/svchost.bin", "modified": (NOW - timedelta(hours=2)).isoformat()},
    ],
    "network_connections": [
        {"local": "0.0.0.0:80", "remote": "various", "state": "LISTEN", "pid": 1234},
        {"local": "10.0.0.12:45678", "remote": "185.220.101.34:4444", "state": "ESTABLISHED", "pid": 9999},
        {"local": "10.0.0.12:3000", "remote": "various", "state": "LISTEN", "pid": 2345},
    ]
}
(TELEMETRY / f"telemetry-{TS}.json").write_text(json.dumps(telemetry, indent=2))
print("[+] Wrote telemetry snapshot")

# ============================================================
# 7. SQLITE INCIDENTS + PATTERNS
# ============================================================
DB_PATH = SCANS / "memory.db"
con = sqlite3.connect(str(DB_PATH))
con.executescript("""
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, type TEXT NOT NULL,
    severity TEXT NOT NULL, scanner TEXT NOT NULL, title TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'open', resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS patterns (
    signature TEXT PRIMARY KEY, first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, hit_count INTEGER NOT NULL DEFAULT 1, severity TEXT NOT NULL
);
""")

incidents = [
    ("MALW-001", "malware_detection", "critical", "ClamAV", "Malware Detected: Win.Trojan.Agent-798345",
     {"path": "/home/kali/Music/webapp/uploads/invoice.pdf.exe", "score": 85}, "open"),
    ("MALW-002", "malware_detection", "critical", "ClamAV", "Malware Detected: Trojan.Downloader.Generic",
     {"path": "/home/kali/Music/suspicious/svchost.bin", "score": 85}, "open"),
    ("MALW-003", "malware_detection", "high", "ClamAV", "Malware Detected: Win.Ransomware.Locky-9903455",
     {"path": "/home/kali/Music/webapp/uploads/readme.scr", "score": 85}, "open"),
    ("YARA-001", "yara_detection", "high", "YARA", "YARA Rule Hit: Suspicious_PowerShell",
     {"rule": "Suspicious_PowerShell", "file": "/home/kali/Music/webapp/uploads/invoice.pdf.exe"}, "open"),
    ("YARA-002", "yara_detection", "critical", "YARA", "YARA Rule Hit: Reverse_Shell_Bash",
     {"rule": "Reverse_Shell_Bash", "file": "/home/kali/Music/suspicious/svchost.bin"}, "open"),
    ("VULN-001", "vulnerability", "critical", "Trivy", "Vulnerability: CVE-2024-21888 in express",
     {"cve": "CVE-2024-21888", "pkg": "express"}, "open"),
    ("VULN-002", "vulnerability", "critical", "Trivy", "Vulnerability: CVE-2024-29041 in lodash",
     {"cve": "CVE-2024-29041", "pkg": "lodash"}, "open"),
    ("VULN-003", "vulnerability", "critical", "Trivy", "Vulnerability: CVE-2024-35195 in requests",
     {"cve": "CVE-2024-35195", "pkg": "requests"}, "open"),
    ("VULN-004", "vulnerability", "high", "Trivy", "Vulnerability: CVE-2023-44487 in node",
     {"cve": "CVE-2023-44487", "pkg": "node"}, "resolved"),
    ("VULN-005", "vulnerability", "high", "Trivy", "Vulnerability: CVE-2024-34062 in flask",
     {"cve": "CVE-2024-34062", "pkg": "flask"}, "open"),
    ("HOST-001", "host_alert", "critical", "Wazuh", "Wazuh Alert: SSH brute-force attack detected",
     {"source_ip": "185.220.101.34", "agent": "web-server-01"}, "open"),
    ("HOST-002", "host_alert", "critical", "Wazuh", "Wazuh Alert: Rootkit detection on web-server-01",
     {"agent": "web-server-01"}, "open"),
    ("HOST-003", "host_alert", "high", "Wazuh", "Wazuh Alert: Privilege escalation attempt",
     {"source_ip": "10.0.0.45", "agent": "db-server-02"}, "resolved"),
]

con.execute("DELETE FROM incidents")
con.execute("DELETE FROM patterns")
for i, (iid, typ, sev, scanner, title, details, status) in enumerate(incidents):
    ts = (NOW - timedelta(hours=len(incidents)-i)).isoformat()
    resolved = (NOW - timedelta(hours=1)).isoformat() if status == "resolved" else None
    con.execute("INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?)",
                (iid, ts, typ, sev, scanner, title, json.dumps(details), status, resolved))

patterns = [
    ("clamav:Win.Trojan.Agent", (NOW - timedelta(days=5)).isoformat(), NOW.isoformat(), 8, "critical"),
    ("clamav:Trojan.Downloader", (NOW - timedelta(days=3)).isoformat(), NOW.isoformat(), 3, "critical"),
    ("yara:Suspicious_PowerShell", (NOW - timedelta(days=7)).isoformat(), NOW.isoformat(), 12, "high"),
    ("yara:Reverse_Shell_Bash", (NOW - timedelta(days=2)).isoformat(), NOW.isoformat(), 2, "critical"),
    ("cve:CVE-2024-21888", (NOW - timedelta(days=10)).isoformat(), NOW.isoformat(), 5, "critical"),
    ("cve:CVE-2023-44487", (NOW - timedelta(days=14)).isoformat(), NOW.isoformat(), 15, "high"),
    ("ssh_bruteforce:185.220.101.34", (NOW - timedelta(days=4)).isoformat(), NOW.isoformat(), 23, "critical"),
]
for sig, first, last, hits, sev in patterns:
    con.execute("INSERT INTO patterns VALUES (?,?,?,?,?)", (sig, first, last, hits, sev))

con.commit()
con.close()
print(f"[+] Populated memory.db: {len(incidents)} incidents, {len(patterns)} patterns")

# ============================================================
# 8. THREAT EVENTS (ThreatSentinel correlation output)
# ============================================================
events = []
sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
for iid, typ, sev, scanner, title, details, status in incidents:
    events.append({"id": iid, "timestamp": NOW.isoformat(), "type": typ,
                   "scanner": scanner, "severity": sev, "title": title,
                   "details": details, "status": status})
events.sort(key=lambda e: sev_order.get(e["severity"], 99))
(SCANS / "threat_events.json").write_text(json.dumps(events, indent=2))
print("[+] Wrote threat_events.json (ThreatSentinel)")

print("\n" + "="*60)
print("  ALL TEST DATA SEEDED SUCCESSFULLY!")
print("  Restart the backend to see everything in the dashboard.")
print("="*60)
