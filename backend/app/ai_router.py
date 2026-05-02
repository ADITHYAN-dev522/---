# backend/app/ai_router.py
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import requests
import json
import os
from pathlib import Path

router = APIRouter()

# Ollama endpoint
OLLAMA_API = os.getenv("OLLAMA_API", "http://localhost:11434/api/generate")

# Default model — change this to whatever you have pulled in Ollama
# e.g. ollama pull qwen2.5:7b-instruct
AI_MODEL = os.getenv("AI_MODEL", "qwen2.5:7b-instruct")

BASE_DIR  = Path(__file__).resolve().parent.parent
SCANS_DIR = BASE_DIR / "scans"

# System prompt for Blue-Team Copilot
SYSTEM_PROMPT = """
You are SentinelNexus Blue-Team Copilot — an expert SOC analyst assistant.
You have access to the latest security scan context (vulnerabilities, malware detections,
YARA rule matches, VirusTotal results, and incident history) provided below.
Your role is to help security analysts understand threats, prioritize response actions,
and provide clear, plain-language explanations.

Rules:
- Be concise, structured, and actionable.
- Always suggest specific next steps.
- Never execute commands yourself — only suggest them.
- Reference CVE IDs and package names when discussing vulnerabilities.
- If asked about malware, reference ClamAV verdict, YARA hits, and VT positives specifically.
- If a question is outside cybersecurity scope, politely redirect.
"""


def _build_context() -> str:
    """Load real scan data from disk to inject as Copilot context."""
    ctx_parts = []

    # Vulnerability summary
    latest_file = SCANS_DIR / "latest.json"
    if latest_file.exists():
        try:
            data = json.loads(latest_file.read_text())
            crit = high = 0
            for _, scanners in data.get("results", {}).items():
                trivy = scanners.get("trivy", {})
                for r in (trivy.get("Results", []) if isinstance(trivy, dict) else []):
                    for v in r.get("Vulnerabilities", []):
                        sev = (v.get("Severity") or "").upper()
                        if sev == "CRITICAL": crit += 1
                        elif sev == "HIGH":   high += 1
            ctx_parts.append(f"[Vulnerability Scan] Timestamp: {data.get('timestamp', 'unknown')} | Critical: {crit} | High: {high}")
        except Exception:
            pass

    # Malware summary
    malware_file = SCANS_DIR / "malware" / "malware_status.json"
    if malware_file.exists():
        try:
            mal = json.loads(malware_file.read_text())
            ctx_parts.append(
                f"[Malware Status] Verdict: {mal.get('verdict')} | "
                f"Risk Score: {mal.get('risk_score')} | "
                f"ClamAV Infections: {mal.get('clamav', {}).get('infected_count', 0)} | "
                f"YARA Hits: {mal.get('yara_hits', 0)} | "
                f"VT Positives: {mal.get('vt_positives', 0)}"
            )
            dets = mal.get("clamav", {}).get("detections", [])
            if dets:
                ctx_parts.append(f"[ClamAV Detections] {', '.join(dets[:5])}")
        except Exception:
            pass

    # Recent incidents from memory
    try:
        from app.services.memory import db as memory
        incidents = memory.get_incidents(status="open", limit=5)
        if incidents:
            summary = "; ".join(f"{i['severity'].upper()}: {i['title']}" for i in incidents)
            ctx_parts.append(f"[Open Incidents] {summary}")
    except Exception:
        pass

    return "\n".join(ctx_parts) if ctx_parts else "No scan data available yet."


class ChatRequest(BaseModel):
    message: str
    context: dict | None = None
    stream: bool = False


@router.post("/ai/chat")
def ai_chat(body: ChatRequest, request: Request):
    # Build context from real scan data
    scan_context = _build_context()

    prompt_parts = [
        SYSTEM_PROMPT.strip(),
        "",
        "=== CURRENT SECURITY CONTEXT ===",
        scan_context,
        "================================",
        "",
    ]

    if body.context:
        prompt_parts.append("Additional context (JSON):")
        prompt_parts.append(str(body.context))

    prompt_parts.append(f"Analyst: {body.message}")
    prompt_parts.append("Copilot:")

    prompt = "\n".join(prompt_parts)

    # Try both uppercase and lowercase just in case
    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("gemini_api_key")
    gemini_error = ""
    
    # ── Try Gemini First ──
    if gemini_key and "your_gemini" not in gemini_key:
        try:
            gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_key}"
            gemini_payload = {"contents": [{"parts": [{"text": prompt}]}]}
            gemini_resp = requests.post(gemini_url, json=gemini_payload, timeout=30)
            gemini_resp.raise_for_status()
            
            gemini_data = gemini_resp.json()
            reply = gemini_data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "Error parsing Gemini response")
            return {"reply": reply, "model": "gemini-2.5-flash"}
        except Exception as e:
            gemini_error = f"Gemini error: {str(e)}"
    else:
        gemini_error = "GEMINI_API_KEY not configured"

    # ── Fallback to Ollama ──
    try:
        ollama_payload = {
            "model":      AI_MODEL,
            "prompt":     prompt,
            "max_tokens": 512,
            "stream":     False,
        }
        resp = requests.post(OLLAMA_API, json=ollama_payload, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        
        if isinstance(data, dict):
            reply = data.get("response") or data.get("generated_text") or (data.get("message") or {}).get("content", "")
            if not reply:
                reply = str(data)
        else:
            reply = str(data)
            
        return {"reply": reply, "model": f"{AI_MODEL} (fallback)"}
        
    except Exception as ollama_e:
        error_msg = f"Both AI providers failed. {gemini_error} | Ollama fallback error: {str(ollama_e)}"
        print(f"\n[!] AI ROUTER ERROR: {error_msg}\n")
        raise HTTPException(status_code=500, detail=error_msg)
