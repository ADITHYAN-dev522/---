
# SentinelNexus – AI-Powered Security Operations Platform

## Overview

SentinelNexus is an AI-driven security operations platform designed to function as an intelligent, modular SOC system.

The platform integrates:

* AI Chatbot (Security Copilot)
* Malware Scanner
* Vulnerability Scanner
* Telemetry Snapshot Monitoring
* Threat Intelligence Correlation Engine

It combines frontend visualization with a backend API engine to simulate real-world SOC workflows including detection, enrichment, prioritization, and response insight.

---

# Architecture

## Frontend

Built with:

* Vite
* TypeScript
* React
* shadcn-ui
* Tailwind CSS

The frontend provides:

* Telemetry snapshot cards
* Threat severity indicators
* Detection charts
* Malware scan results
* Vulnerability findings
* AI chatbot interface
* Threat intelligence summaries

---

## Backend

Built with:

* FastAPI
* Uvicorn
* Pydantic
* Python

The backend powers:

### 1. AI Security Chatbot

A SOC-style assistant capable of:

* Explaining detected threats
* Interpreting telemetry data
* Providing mitigation guidance
* Summarizing malware or vulnerability reports

---

### 2. Malware Scanner Module

Simulates malware detection logic including:

* File signature analysis
* Suspicious behavior indicators
* Risk scoring
* Classification output

---

### 3. Vulnerability Scanner Module

Performs structured vulnerability checks such as:

* Service exposure validation
* Misconfiguration detection
* Known vulnerability mapping
* Severity categorization

Outputs:

* Vulnerability list
* CVSS-style severity
* Remediation recommendations

---

### 4. Telemetry Snapshot Module

Displays real-time styled system data such as:

* Active processes
* Network activity
* Event logs
* Alert triggers

This module feeds data into detection logic and visualization components.

---

### 5. Threat Intelligence Engine

Correlates:

* Indicators of Compromise (IOCs)
* IP reputation
* Known malware families
* Behavioral anomalies

Used to:

* Enrich alerts
* Improve prioritization
* Provide contextual threat analysis

# Running the Project

## Backend Setup

Activate virtual environment:

```bash
source venv/bin/activate      # Linux
venv\Scripts\activate         # Windows
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run server:

```bash
uvicorn main:app --reload
```

Backend default:

```
http://127.0.0.1:8000
```

---

## Frontend Setup

Navigate to frontend directory:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start development server:

```bash
npm run dev
```

Frontend default:

```
http://localhost:5173
```

---

# Key Features

* Modular SOC-style design
* AI-driven security analysis
* Interactive telemetry dashboard
* Malware and vulnerability scanning
* Threat intelligence enrichment
* Clean separation of frontend and backend

---

# Purpose

This project is designed as:

* A cybersecurity engineering portfolio system
* A SOC simulation platform
* A foundation for building an autonomous AI-powered security engine

---

# Future Enhancements

* Automated response orchestration
* Graph-based threat correlation
* Memory-based threat learning
* Real log ingestion
* Red team simulation engine
* Risk scoring engine

---
