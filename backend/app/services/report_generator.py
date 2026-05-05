"""
report_generator.py — Professional PDF report generation for SentinelNexus.

Generates a comprehensive security assessment report containing:
  - Executive summary with risk scores
  - Vulnerability findings (Trivy, OSV, Semgrep, Nuclei, Bandit)
  - Malware analysis (ClamAV, YARA, VirusTotal)
  - Threat intelligence (Wazuh alerts)
  - Incident history
  - Remediation recommendations
"""

import json
from pathlib import Path
from datetime import datetime
from io import BytesIO

try:
    from fpdf import FPDF
    _fpdf_ok = True
except ImportError:
    _fpdf_ok = False
    class FPDF: pass  # Dummy class to prevent NameError on class definition


# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent.parent
SCANS_DIR   = BASE_DIR / "scans"
MALWARE_DIR = SCANS_DIR / "malware"


def _load_json(path: Path) -> dict | list | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


# ─── Custom PDF class ────────────────────────────────────────────────────────

class SentinelReport(FPDF):
    """Custom FPDF subclass with branded header/footer."""

    def __init__(self):
        super().__init__("P", "mm", "A4")
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(15, 15, 15)
        self._report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Header ───────────────────────────────────────────────────────────
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(0, 180, 220)
        self.cell(0, 8, "SentinelNexus", ln=False)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, f"Security Assessment Report  |  {self._report_time}", ln=True, align="R")
        self.set_draw_color(0, 180, 220)
        self.set_line_width(0.4)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)

    # ── Footer ───────────────────────────────────────────────────────────
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(140, 140, 140)
        self.cell(0, 10, f"SentinelNexus v1.0  |  AI-Powered SOC Platform  |  Page {self.page_no()}/{{nb}}", align="C")

    # ── Section heading ──────────────────────────────────────────────────
    def section_title(self, title: str, r=0, g=180, b=220):
        self.ln(4)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(r, g, b)
        self.cell(0, 8, title, ln=True)
        self.set_draw_color(r, g, b)
        self.set_line_width(0.3)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(3)
        self.set_text_color(40, 40, 40)

    # ── Sub-heading ──────────────────────────────────────────────────────
    def sub_heading(self, text: str):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(60, 60, 60)
        self.cell(0, 7, text, ln=True)
        self.ln(1)
        self.set_text_color(40, 40, 40)

    # ── Body text ────────────────────────────────────────────────────────
    def body_text(self, text: str, size=9):
        self.set_font("Helvetica", "", size)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 5, text)
        self.ln(1)

    # ── Severity badge ───────────────────────────────────────────────────
    def severity_badge(self, sev: str):
        colors = {
            "critical": (239, 68, 68),
            "high":     (249, 115, 22),
            "medium":   (234, 179, 8),
            "low":      (16, 185, 129),
            "info":     (100, 116, 139),
        }
        r, g, b = colors.get(sev.lower(), (100, 100, 100))
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 7)
        w = self.get_string_width(sev.upper()) + 6
        self.cell(w, 5, sev.upper(), fill=True, ln=False)
        self.set_text_color(40, 40, 40)

    # ── Key-value row ────────────────────────────────────────────────────
    def kv_row(self, key: str, value: str, bold_val=False):
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(80, 80, 80)
        self.cell(45, 5, key + ":", ln=False)
        self.set_font("Helvetica", "B" if bold_val else "", 8)
        self.set_text_color(40, 40, 40)
        self.cell(0, 5, str(value)[:120], ln=True)

    # ── Table ────────────────────────────────────────────────────────────
    def simple_table(self, headers: list[str], rows: list[list[str]], col_widths: list[int] | None = None):
        if not rows:
            return
        w_total = 180
        if col_widths is None:
            col_widths = [w_total // len(headers)] * len(headers)

        # Header
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(230, 240, 250)
        self.set_text_color(30, 30, 30)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 6, h, border=1, fill=True)
        self.ln()

        # Rows
        self.set_font("Helvetica", "", 7)
        self.set_text_color(50, 50, 50)
        for row in rows[:60]:  # Cap at 60 rows to avoid huge PDFs
            max_h = 6
            for i, cell in enumerate(row):
                self.cell(col_widths[i], max_h, str(cell)[:50], border=1)
            self.ln()


# ─── Report Builder ───────────────────────────────────────────────────────────

def generate_report() -> bytes | None:
    """Generate a comprehensive PDF security report and return the bytes."""
    if not _fpdf_ok:
        return None

    pdf = SentinelReport()
    pdf.alias_nb_pages()
    pdf.add_page()

    # ================================================================
    # COVER / EXECUTIVE SUMMARY
    # ================================================================
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(0, 180, 220)
    pdf.ln(20)
    pdf.cell(0, 12, "Security Assessment Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, "SentinelNexus - AI-Powered SOC Platform", ln=True, align="C")
    pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}", ln=True, align="C")
    pdf.ln(10)

    # Load all data sources
    scan_data   = _load_json(SCANS_DIR / "latest.json")
    malware     = _load_json(MALWARE_DIR / "malware_status.json")
    yara_data   = _load_json(MALWARE_DIR / "yara_results.json")
    vt_data     = _load_json(MALWARE_DIR / "vt_results.json")

    # ── Executive summary stats ──
    pdf.section_title("1. Executive Summary")

    # Count vulnerability findings
    trivy_count = osv_count = semgrep_count = nuclei_count = bandit_count = 0
    critical_count = high_count = 0
    if scan_data and scan_data.get("results"):
        for _dir, bucket in scan_data["results"].items():
            # Trivy
            trivy = bucket.get("trivy", {})
            if isinstance(trivy, dict):
                for result_block in trivy.get("Results", []):
                    vulns = result_block.get("Vulnerabilities", [])
                    trivy_count += len(vulns)
                    for v in vulns:
                        s = (v.get("Severity") or "").upper()
                        if s == "CRITICAL":
                            critical_count += 1
                        elif s == "HIGH":
                            high_count += 1
            # OSV
            osv = bucket.get("osv", {})
            if isinstance(osv, dict):
                for r in osv.get("results", []):
                    osv_count += len(r.get("vulns", []))
            # Semgrep
            semgrep = bucket.get("semgrep", {})
            if isinstance(semgrep, dict):
                semgrep_count += len(semgrep.get("results", []))
            # Nuclei
            nuclei = bucket.get("nuclei", {})
            if isinstance(nuclei, dict):
                nuclei_count += len(nuclei.get("findings", []))
            # Bandit
            bandit = bucket.get("bandit", {})
            if isinstance(bandit, dict):
                bandit_count += len(bandit.get("results", []))

    total_vulns = trivy_count + osv_count + semgrep_count + nuclei_count + bandit_count

    pdf.body_text(
        "This report provides a comprehensive security assessment of the monitored infrastructure. "
        "It covers vulnerability scanning, malware analysis, and threat intelligence data collected by "
        "SentinelNexus automated pipelines."
    )

    pdf.kv_row("Report Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    pdf.kv_row("Total Vulnerability Findings", str(total_vulns), bold_val=True)
    pdf.kv_row("Critical Vulnerabilities", str(critical_count), bold_val=True)
    pdf.kv_row("High Vulnerabilities", str(high_count), bold_val=True)
    if malware:
        pdf.kv_row("Malware Verdict", malware.get("verdict", "N/A"), bold_val=True)
        pdf.kv_row("Malware Risk Score", f"{malware.get('risk_score', 0)}/100", bold_val=True)

    pdf.ln(3)
    pdf.sub_heading("Scanner Coverage")
    pdf.simple_table(
        ["Scanner", "Type", "Findings"],
        [
            ["Trivy",   "Dependency CVE Scanner",     str(trivy_count)],
            ["OSV",     "Open Source Vuln Database",   str(osv_count)],
            ["Semgrep", "Static Code Analysis (SAST)", str(semgrep_count)],
            ["Nuclei",  "Template-Based Vuln Scanner", str(nuclei_count)],
            ["Bandit",  "Python Security Linter",      str(bandit_count)],
        ],
        [50, 80, 50],
    )

    # ================================================================
    # VULNERABILITY FINDINGS
    # ================================================================
    pdf.add_page()
    pdf.section_title("2. Vulnerability Findings", 249, 115, 22)

    if scan_data and scan_data.get("results"):
        for scan_dir, bucket in scan_data["results"].items():
            pdf.sub_heading(f"Target: {scan_dir}")

            # ── Trivy ──
            trivy = bucket.get("trivy", {})
            if isinstance(trivy, dict) and not trivy.get("error"):
                trivy_vulns = []
                for result_block in trivy.get("Results", []):
                    trivy_vulns.extend(result_block.get("Vulnerabilities", []))
                if trivy_vulns:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(0, 6, f"Trivy ({len(trivy_vulns)} findings)", ln=True)
                    rows = []
                    for v in trivy_vulns[:30]:
                        rows.append([
                            v.get("VulnerabilityID", ""),
                            (v.get("Severity", "")).upper(),
                            v.get("PkgName", ""),
                            v.get("InstalledVersion", ""),
                            v.get("FixedVersion", "N/A"),
                        ])
                    pdf.simple_table(
                        ["CVE ID", "Severity", "Package", "Installed", "Fixed"],
                        rows,
                        [35, 22, 45, 38, 40],
                    )
                    pdf.ln(3)

            # ── OSV ──
            osv = bucket.get("osv", {})
            if isinstance(osv, dict) and not osv.get("error"):
                osv_vulns = []
                for r in osv.get("results", []):
                    osv_vulns.extend(r.get("vulns", []))
                if osv_vulns:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(0, 6, f"OSV Scanner ({len(osv_vulns)} findings)", ln=True)
                    rows = []
                    for v in osv_vulns[:20]:
                        aliases = ", ".join(v.get("aliases", [])[:2])
                        rows.append([
                            v.get("id", ""),
                            aliases,
                            (v.get("summary", ""))[:60],
                        ])
                    pdf.simple_table(
                        ["ID", "CVE Aliases", "Summary"],
                        rows,
                        [40, 50, 90],
                    )
                    pdf.ln(3)

            # ── Semgrep ──
            semgrep = bucket.get("semgrep", {})
            if isinstance(semgrep, dict) and not semgrep.get("error"):
                findings = semgrep.get("results", [])
                if findings:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(0, 6, f"Semgrep SAST ({len(findings)} findings)", ln=True)
                    rows = []
                    for f in findings[:20]:
                        sev = f.get("extra", {}).get("severity", "INFO")
                        rows.append([
                            sev.upper(),
                            (f.get("check_id", ""))[:40],
                            f.get("path", ""),
                            str(f.get("start", {}).get("line", "")),
                        ])
                    pdf.simple_table(
                        ["Severity", "Rule", "File", "Line"],
                        rows,
                        [22, 65, 70, 23],
                    )
                    pdf.ln(3)

            # ── Nuclei ──
            nuclei = bucket.get("nuclei", {})
            if isinstance(nuclei, dict) and not nuclei.get("error"):
                findings = nuclei.get("findings", [])
                if findings:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(0, 6, f"Nuclei ({len(findings)} findings)", ln=True)
                    rows = []
                    for f in findings[:20]:
                        info = f.get("info", {})
                        rows.append([
                            info.get("severity", "").upper(),
                            info.get("name", f.get("template-id", ""))[:40],
                            f.get("matched-at", f.get("host", ""))[:50],
                            ", ".join(info.get("tags", [])[:3]),
                        ])
                    pdf.simple_table(
                        ["Severity", "Template", "Matched At", "Tags"],
                        rows,
                        [22, 55, 60, 43],
                    )
                    pdf.ln(3)

            # ── Bandit ──
            bandit = bucket.get("bandit", {})
            if isinstance(bandit, dict) and not bandit.get("error"):
                results = bandit.get("results", [])
                if results:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(0, 6, f"Bandit Python SAST ({len(results)} findings)", ln=True)
                    rows = []
                    for r in results[:20]:
                        rows.append([
                            r.get("issue_severity", "").upper(),
                            r.get("issue_confidence", ""),
                            r.get("test_id", ""),
                            (r.get("issue_text", ""))[:45],
                            f"{r.get('filename', '')}:{r.get('line_number', '')}",
                        ])
                    pdf.simple_table(
                        ["Severity", "Confidence", "Test ID", "Issue", "Location"],
                        rows,
                        [22, 25, 20, 63, 50],
                    )
                    pdf.ln(3)

    else:
        pdf.body_text("No vulnerability scan data available. Run a scan to populate this section.")

    # ================================================================
    # MALWARE ANALYSIS
    # ================================================================
    pdf.add_page()
    pdf.section_title("3. Malware Analysis", 239, 68, 68)

    if malware:
        pdf.kv_row("Scan Timestamp", malware.get("timestamp", "N/A"))
        pdf.kv_row("Overall Verdict", malware.get("verdict", "N/A"), bold_val=True)
        pdf.kv_row("Risk Score", f"{malware.get('risk_score', 0)}/100", bold_val=True)
        pdf.kv_row("ClamAV Infections", str(malware.get("clamav", {}).get("infected_count", 0)))
        pdf.kv_row("YARA Rule Hits", str(malware.get("yara_hits", 0)))
        pdf.kv_row("VirusTotal Positives", str(malware.get("vt_positives", 0)))
        pdf.ln(3)

        # ClamAV detections
        clamav = malware.get("clamav", {})
        detections = clamav.get("detections", [])
        if detections:
            pdf.sub_heading("ClamAV Detections")
            for det in detections[:15]:
                pdf.set_font("Courier", "", 7)
                pdf.multi_cell(0, 4, det[:120])
            pdf.ln(2)

        # Recommendations
        recs = malware.get("recommended_actions", [])
        if recs:
            pdf.sub_heading("Recommended Actions")
            for rec in recs:
                pdf.set_font("Helvetica", "B", 8)
                level = rec.get("level", "info").upper()
                pdf.severity_badge(level)
                pdf.set_font("Helvetica", "", 8)
                pdf.cell(5, 5, "")
                pdf.cell(0, 5, rec.get("message", "")[:100], ln=True)
            pdf.ln(2)
    else:
        pdf.body_text("No malware scan data available.")

    # YARA details
    if yara_data and isinstance(yara_data, list):
        hits = [y for y in yara_data if y.get("matches")]
        if hits:
            pdf.sub_heading(f"YARA Rule Matches ({len(hits)} files)")
            rows = []
            for y in hits[:15]:
                rules = ", ".join(m.get("rule", "") for m in y.get("matches", []))
                rows.append([
                    y.get("file", "")[-50:],
                    rules[:40],
                    (y.get("sha256", "") or "")[:20] + "...",
                ])
            pdf.simple_table(["File", "Rules Matched", "SHA-256"], rows, [70, 55, 55])
            pdf.ln(2)

    # VirusTotal details
    if vt_data and isinstance(vt_data, list):
        flagged = [v for v in vt_data if v.get("positives", 0) > 0]
        if flagged:
            pdf.sub_heading(f"VirusTotal Flagged Hashes ({len(flagged)})")
            rows = []
            for v in flagged[:10]:
                rows.append([
                    (v.get("sha256", ""))[:24] + "...",
                    f"{v.get('positives', 0)}/{v.get('total_engines', 0)}",
                    v.get("malware_family", "N/A") or "N/A",
                    v.get("threat_label", "N/A") or "N/A",
                ])
            pdf.simple_table(["SHA-256", "Detections", "Family", "Label"], rows, [55, 30, 45, 50])
            pdf.ln(2)

    # ================================================================
    # THREAT INTELLIGENCE
    # ================================================================
    wazuh_data = _load_json(SCANS_DIR / "wazuh_alerts.json")
    if wazuh_data and isinstance(wazuh_data, list) and len(wazuh_data) > 0:
        pdf.add_page()
        pdf.section_title("4. Threat Intelligence (Wazuh SIEM)", 139, 92, 246)
        pdf.body_text(f"Total Wazuh alerts collected: {len(wazuh_data)}")

        rows = []
        for a in wazuh_data[:25]:
            rows.append([
                str(a.get("severity", "")),
                a.get("rule", "")[:50],
                a.get("agent", "")[:20],
                a.get("timestamp", "")[:19],
            ])
        pdf.simple_table(["Level", "Rule", "Agent", "Timestamp"], rows, [15, 85, 35, 45])

    # ================================================================
    # INCIDENT HISTORY
    # ================================================================
    try:
        from app.services.memory import db as memory
        incidents = memory.get_incidents(limit=50)
        if incidents:
            pdf.add_page()
            pdf.section_title("5. Incident History", 249, 115, 22)
            pdf.body_text(f"Total incidents in database: {len(incidents)}")

            stats = memory.get_stats()
            if stats:
                pdf.kv_row("Open Incidents", str(stats.get("open", 0)), bold_val=True)
                pdf.kv_row("Resolved", str(stats.get("resolved", 0)))
                pdf.kv_row("Recurring Patterns", str(stats.get("recurring_patterns", 0)))
                pdf.ln(3)

            rows = []
            for inc in incidents[:30]:
                rows.append([
                    inc.get("severity", ""),
                    inc.get("scanner", ""),
                    inc.get("title", "")[:45],
                    inc.get("status", ""),
                    inc.get("timestamp", "")[:19],
                ])
            pdf.simple_table(
                ["Severity", "Scanner", "Title", "Status", "Timestamp"],
                rows,
                [22, 25, 63, 22, 48],
            )
    except Exception:
        pass

    # ================================================================
    # REMEDIATION (PatchMaster)
    # ================================================================
    try:
        from app.services.patchmaster import advisor
        recs = advisor.get_recommendations(limit=30)
        if recs:
            pdf.add_page()
            pdf.section_title("6. Remediation Recommendations (PatchMaster)", 16, 185, 129)
            pdf.body_text(f"{len(recs)} actionable fix commands generated from scan results.")

            rows = []
            for r in recs[:25]:
                rows.append([
                    r.get("severity", "").upper(),
                    r.get("cve", ""),
                    r.get("package", ""),
                    r.get("fix_command", "")[:50],
                ])
            pdf.simple_table(
                ["Severity", "CVE", "Package", "Fix Command"],
                rows,
                [22, 35, 40, 83],
            )
    except Exception:
        pass

    # ================================================================
    # FOOTER NOTE
    # ================================================================
    pdf.add_page()
    pdf.section_title("Disclaimer")
    pdf.body_text(
        "This report was automatically generated by SentinelNexus, an AI-powered Security Operations "
        "Center platform. The findings are based on automated scans and should be verified by a qualified "
        "security analyst before taking remediation action. False positives may exist. This report is "
        "confidential and intended for authorized personnel only."
    )
    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, "End of Report", ln=True, align="C")
    pdf.cell(0, 6, f"SentinelNexus v1.0 - {datetime.now().year}", ln=True, align="C")

    return pdf.output()
