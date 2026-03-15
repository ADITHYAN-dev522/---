# 🛡️ SentinelNexus — AI-Powered Security Operations Platform

> A modular, AI-driven SOC (Security Operations Center) platform built for security analysts and engineers. SentinelNexus integrates real-time threat detection, CVE-mapped vulnerability scanning, malware analysis, and an intelligent AI copilot — all in a single platform.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Prerequisites & Tool Installation](#prerequisites--tool-installation)
   - [OSV-Scanner](#1-osv-scanner)
   - [Trivy](#2-trivy)
   - [Semgrep](#3-semgrep)
   - [ClamAV](#4-clamav)
   - [Wazuh](#5-wazuh)
5. [Running the Project](#running-the-project)
   - [Backend](#backend-setup)
   - [Frontend](#frontend-setup)
6. [API Reference](#api-reference)
7. [Environment Variables](#environment-variables)
8. [Project Structure](#project-structure)

---

## Overview

SentinelNexus is a full-stack security operations platform designed to simulate and assist real-world SOC workflows. It connects a React + TypeScript frontend to a FastAPI backend that orchestrates multiple open-source security scanners and an AI copilot.

**What it does:**
- Runs **Trivy**, **OSV-Scanner**, and **Semgrep** to detect CVEs in packages and code
- Runs **ClamAV** + **YARA** + **VirusTotal** for malware detection
- Collects host telemetry (processes, network, services, software)
- Correlates threats using the **ThreatSentinel** engine
- Provides an **AI Security Analyst chatbot** that can explain findings and suggest remediations

---

## Architecture

```
SentinelNexus/
├── backend/              # FastAPI Python backend
│   ├── main.py           # Entry point
│   ├── auto_scanner.py   # Scheduled scan orchestrator
│   ├── requirements.txt
│   └── app/
│       ├── routes.py     # All API endpoints
│       ├── ai_router.py  # AI chatbot endpoint
│       └── services/
│           ├── telemetry/         # Host telemetry collectors
│           ├── yara_engine/       # YARA malware scanning
│           ├── virustotal/        # VirusTotal API lookups
│           ├── threat_sentinel/   # Threat correlation engine
│           ├── patchmaster/       # Remediation recommendations
│           ├── risk_engine/       # Risk scoring
│           ├── memory/            # SQLite incident store
│           └── threat_intelligence/wazuh/  # Wazuh integration
│
└── src/                  # React + TypeScript frontend
    ├── App.tsx            # Root component + routing
    ├── pages/
    │   ├── Dashboard.tsx
    │   ├── VulnerabilityAssessment.tsx   # CVE scanner UI
    │   ├── Malware.tsx
    │   ├── Detections.tsx
    │   ├── Incidents.tsx
    │   ├── Intelligence.tsx
    │   └── Response.tsx
    └── components/
        ├── chat/FloatingAIChatbox.tsx    # Global AI assistant
        └── layout/                       # Sidebar, Header, Footer
```

**Scan Flow:**
```
auto_scanner.py (startup + scheduled)
    ├── run_all_scans()        → OSV + Trivy + Semgrep → scans/latest.json
    ├── run_malware_scan()     → ClamAV + YARA + VirusTotal → scans/malware/
    ├── run_telemetry_snapshot() → scans/telemetry/
    └── run_correlation()      → ThreatSentinel → memory DB
```

---

## Features

| Feature | Description |
|---|---|
| 🔍 **CVE Vulnerability Scanner** | Trivy + OSV + Semgrep with analyst-ready output including CVE IDs, CVSS scores, NVD links, CWE/OWASP mappings |
| 🦠 **Malware Scanner** | ClamAV antivirus + YARA rule matching + VirusTotal hash lookup |
| 📡 **Live Telemetry** | Real-time host inventory: processes, network connections, installed software, services |
| 🧠 **AI Security Analyst** | Floating chatbot that explains findings, maps to CVEs, and suggests remediations |
| 📌 **Pin Data to AI** | Paste any scan output, CVE details, or log lines into the chatbot for instant analysis |
| 🔗 **Threat Correlation** | ThreatSentinel engine correlates events across all scanners |
| 📊 **Risk Scoring** | Automated risk score based on combined scanner verdict |
| 🩹 **PatchMaster** | Remediation recommendations with priority levels |
| 🔒 **Wazuh Integration** | Pull alerts from Wazuh indexer for SIEM correlation |

---

## Prerequisites & Tool Installation

### 1. OSV-Scanner

OSV-Scanner checks your dependencies against the [Open Source Vulnerabilities](https://osv.dev) database.

**Kali / Ubuntu:**
```bash
# Option A: Go install (recommended)
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
export PATH=$PATH:$(go env GOPATH)/bin

# Option B: Download binary release
curl -LO https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
chmod +x osv-scanner_linux_amd64
sudo mv osv-scanner_linux_amd64 /usr/local/bin/osv-scanner

# Verify
osv-scanner --version
```

**Windows (PowerShell):**
```powershell
# Option A: Using Go
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Option B: Download .exe from GitHub Releases
# https://github.com/google/osv-scanner/releases/latest
# Download: osv-scanner_windows_amd64.exe
# Rename to osv-scanner.exe and place in a folder on your PATH
# Example:
Move-Item osv-scanner_windows_amd64.exe C:\tools\osv-scanner.exe
$env:PATH += ";C:\tools"

# Verify
osv-scanner --version
```

**Usage:**
```bash
# Scan a directory recursively
osv-scanner --format=json --recursive /path/to/project

# Scan a specific lockfile
osv-scanner --lockfile package-lock.json
```

---

### 2. Trivy

Trivy scans OS packages, language libraries, container images, and Kubernetes configs for CVEs.

**Kali / Ubuntu:**
```bash
# Add Trivy repo (recommended)
sudo apt-get install -y wget apt-transport-https gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor \
  -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy

# OR using the install script
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Verify
trivy --version
```

**Windows (PowerShell):**
```powershell
# Option A: Using Scoop
scoop install trivy

# Option B: Using Winget
winget install AquaSecurity.Trivy

# Option C: Manual download
# https://github.com/aquasecurity/trivy/releases/latest
# Download: trivy_<version>_windows-64bit.zip
# Extract trivy.exe and add to PATH

# Verify
trivy --version
```

**Usage:**
```bash
# Scan filesystem for vulnerabilities
trivy fs --format json --scanners vuln /path/to/project

# Scan a Docker image
trivy image --format json nginx:latest

# Scan with SBOM output
trivy fs --format cyclonedx /path/to/project
```

---

### 3. Semgrep

Semgrep performs static analysis to find security bugs, anti-patterns, and code vulnerabilities.

**Kali / Ubuntu:**
```bash
# Install via pip (Python 3.8+)
pip install semgrep

# OR using the install script
curl -fsSL https://semgrep.dev/get-semgrep.sh | sh

# Verify
semgrep --version
```

**Windows (PowerShell):**
```powershell
# Install via pip
pip install semgrep

# Verify
semgrep --version
```

> **Note:** On Windows, Semgrep works via WSL2 for full functionality. Run it inside WSL for best results.

**Usage:**
```bash
# Scan using the CI ruleset (recommended for security)
semgrep --json --config=p/ci /path/to/code

# Scan for OWASP Top 10
semgrep --json --config=p/owasp-top-ten /path/to/code

# Scan using a specific ruleset
semgrep --json --config=p/python /path/to/python/project

# Available rule packs: p/python, p/javascript, p/java, p/go, p/ci, p/owasp-top-ten
```

---

### 4. ClamAV

ClamAV is an open-source antivirus engine for detecting malware, viruses, and trojans.

**Kali / Ubuntu:**
```bash
# Install
sudo apt-get update
sudo apt-get install -y clamav clamav-daemon

# Update virus definitions (required before first scan)
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam

# Start ClamAV daemon (optional, for faster scanning)
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon

# Verify
clamscan --version
```

**Windows:**
```powershell
# Option A: Download installer from official site
# https://www.clamav.net/downloads
# Run the .msi installer

# Option B: Using Winget
winget install ClamAV.ClamAV

# After install, update definitions:
cd "C:\Program Files\ClamAV"
.\freshclam.exe

# Verify
clamscan.exe --version
```

**Usage:**
```bash
# Recursive scan, show only infected files
clamscan -r --infected /path/to/scan

# Full scan with summary
clamscan -r --bell /path/to/scan

# Scan and remove infected (use with caution!)
clamscan -r --remove /path/to/scan
```

---

### 5. Wazuh

Wazuh is an open-source SIEM/XDR platform. SentinelNexus connects to the Wazuh indexer API to pull security alerts.

**Kali / Ubuntu (Wazuh Indexer + Manager):**
```bash
# Install using the Wazuh installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Edit config.yml with your node/IP info, then:
sudo bash wazuh-install.sh --wazuh-indexer node-1
sudo bash wazuh-install.sh --start-cluster
sudo bash wazuh-install.sh --wazuh-server wazuh-1
sudo bash wazuh-install.sh --wazuh-dashboard dashboard

# OR: Quick all-in-one install (for testing)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
```

**Windows (Wazuh Agent only):**
```powershell
# Download Windows agent MSI
# https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.x-1.msi

# Install silently (replace WAZUH_MANAGER with your manager IP)
msiexec.exe /i wazuh-agent-4.7.x-1.msi /q WAZUH_MANAGER="192.168.1.x" WAZUH_REGISTRATION_SERVER="192.168.1.x"

# Start the service
NET START WazuhSvc

# Check status
sc query WazuhSvc
```

**Configuring SentinelNexus to connect to Wazuh:**

Edit `backend/.env`:
```env
WAZUH_URL=https://your-wazuh-indexer-ip:9200
WAZUH_USER=admin
WAZUH_PASS=your_admin_password
```

---

## Running the Project

### Backend Setup

**Step 1: Navigate to the backend directory**
```bash
cd backend
```

**Step 2: Create and activate a virtual environment**
```bash
# Linux / macOS / Kali
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1

# Windows (Command Prompt)
venv\Scripts\activate.bat
```

**Step 3: Install Python dependencies**
```bash
pip install -r requirements.txt
```

**Step 4: Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your API keys and config (see Environment Variables below)
```

**Step 5: Start the backend server**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Backend runs at: `http://localhost:8000`  
API docs (interactive): `http://localhost:8000/docs`

**Running scans manually** (optionally, the backend runs them automatically on startup):
```bash
python -c "from auto_scanner import run_all_scans; run_all_scans()"
```

---

### Frontend Setup

**Step 1: Navigate to the project root**
```bash
cd SentinelNexus_101-main   # project root (where package.json is)
```

**Step 2: Install Node.js dependencies**
```bash
npm install
```
> Requires Node.js 18+ and npm 9+. Install from [nodejs.org](https://nodejs.org).

**Step 3: Start the development server**
```bash
npm run dev
```

Frontend runs at: `http://localhost:5173`

> **Important:** The frontend talks to the backend at `http://localhost:8000`. Make sure the backend is running before using the frontend.

---

## API Reference

### Health
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Backend health check |

### Vulnerability Scanning
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/scan/results` | Latest combined scan results (Trivy + OSV + Semgrep) |
| GET | `/api/scan/trivy?target_path=...` | On-demand Trivy scan |
| GET | `/api/scan/osv?target_path=...` | On-demand OSV scan |
| GET | `/api/scan/semgrep?target_path=...` | On-demand Semgrep scan |

### Malware
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/malware/status` | Latest malware scan verdict + risk score |
| GET | `/api/malware/history` | Historical malware scan records |
| GET | `/api/malware/yara-results` | YARA rule match results |
| GET | `/api/malware/vt-results` | VirusTotal hash lookup results |

### Telemetry
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/telemetry/latest` | Latest telemetry snapshot |
| GET | `/api/telemetry/history` | Historical telemetry records |

### Incidents & Memory
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/memory/incidents` | List all incidents (filter by status/severity) |
| GET | `/api/memory/stats` | Incident statistics |
| PATCH | `/api/memory/incidents/{id}/resolve` | Resolve an incident |

### Threat Intelligence
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/threat-sentinel/events` | Correlated threat events |
| POST | `/api/threat-sentinel/correlate` | Trigger correlation manually |
| GET | `/api/threat-intel/wazuh/alerts` | Wazuh alerts (normalized) |

### Risk & Remediation
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/risk/score` | Current risk score |
| GET | `/api/patchmaster/recommendations` | Remediation recommendations |

### AI Chatbot
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/ai/chat` | AI chat (body: `{ message, context }`) |

---

## Environment Variables

Create `backend/.env` from `.env.example`:

```env
# VirusTotal API key (get free key at virustotal.com)
VT_API_KEY=your_virustotal_api_key

# Wazuh Indexer connection
WAZUH_URL=https://localhost:9200
WAZUH_USER=admin
WAZUH_PASS=SecretPassword

# AI model endpoint (Qwen or other local LLM via Ollama, LM Studio, etc.)
AI_MODEL_URL=http://localhost:11434/api/generate
AI_MODEL_NAME=qwen2.5:7b

# Scan directories (comma-separated paths to scan)
SCAN_DIRS=/home/kali/projects,/var/www
MALWARE_SCAN_DIRS=/home/kali/downloads,/tmp
```

---

## Project Structure

```
SentinelNexus_101-main/
│
├── backend/
│   ├── main.py               # FastAPI app + CORS + router mounting
│   ├── auto_scanner.py       # Scan scheduler (APScheduler)
│   ├── requirements.txt      # Python dependencies
│   ├── .env.example          # Environment variable template
│   └── app/
│       ├── routes.py         # Main API routes (scan, malware, telemetry, etc.)
│       ├── ai_router.py      # AI chat endpoint
│       └── services/
│           ├── asset_inventory/    # Host info + asset tags
│           ├── telemetry/          # Processes, network, services, files, software
│           ├── yara_engine/        # YARA scanning engine
│           ├── virustotal/         # VT API hash lookups
│           ├── threat_sentinel/    # Event correlation
│           ├── threat_intelligence/wazuh/  # Wazuh indexer client
│           ├── memory/             # SQLite incident database
│           ├── patchmaster/        # Remediation advisor
│           └── risk_engine/        # Risk score computation
│
├── src/                      # React frontend
│   ├── App.tsx               # Root: routing + global FloatingAIChatbox
│   ├── pages/
│   │   ├── Dashboard.tsx     # SOC dashboard overview
│   │   ├── VulnerabilityAssessment.tsx  # Tabbed CVE scanner UI
│   │   ├── Malware.tsx       # ClamAV + YARA + VT results
│   │   ├── Detections.tsx    # Detection events
│   │   ├── Incidents.tsx     # Incident timeline
│   │   ├── Intelligence.tsx  # Threat intelligence feed
│   │   └── Response.tsx      # Response actions
│   └── components/
│       ├── chat/FloatingAIChatbox.tsx  # AI assistant (pin data, chat)
│       ├── layout/           # Sidebar, Header, Footer, Layout
│       └── ui/               # shadcn/ui components
│
├── package.json              # Frontend dependencies
└── vite.config.ts            # Vite build config
```

---

## Key Technologies

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui, Framer Motion |
| Backend | FastAPI, Uvicorn, Pydantic v2, APScheduler |
| Vulnerability Scanners | Trivy, OSV-Scanner, Semgrep |
| Malware Scanners | ClamAV, YARA, VirusTotal API |
| SIEM | Wazuh (optional) |
| AI Model | Qwen 2.5 / any OpenAI-compatible local LLM |
| Database | SQLite (incidents + memory) |

---

## Troubleshooting

**Backend won't start:**
- Make sure your virtual environment is activated
- Run `pip install -r requirements.txt` again
- Check Python version: `python --version` (requires 3.11+)

**Scanners not found:**
- Make sure `trivy`, `osv-scanner`, `semgrep`, and `clamscan` are on your system `PATH`
- Test each: `trivy --version`, `osv-scanner --version`, `semgrep --version`, `clamscan --version`

**Frontend shows "No scan results yet":**
- The backend runs scans automatically on startup — wait 1–2 minutes for the first scan to complete
- Check backend logs in the terminal running `uvicorn`

**AI chatbot shows "backend unreachable":**
- Make sure the backend is running on port 8000
- Check that your AI model (e.g., Ollama) is accessible at the URL in your `.env`

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built for security engineers, analysts, and researchers who need a unified, AI-assisted SOC simulation platform.*
