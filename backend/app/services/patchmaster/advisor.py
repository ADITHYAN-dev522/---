"""
PatchMaster — CVE-to-Remediation Advisor.

Maps detected vulnerabilities (from Trivy/OSV scan results) to
actionable remediation commands. Groups suggestions by package manager
and severity so analysts know exactly what to run.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_DIR  = Path(__file__).resolve().parent.parent.parent.parent
SCANS_DIR = BASE_DIR / "scans"


# ─── Package manager detection ────────────────────────────────────────────────
def _pkg_mgr(pkg_type: str, pkg_name: str) -> str:
    t = (pkg_type or "").lower()
    if "pip" in t or "python" in t:    return "pip"
    if "npm" in t or "node" in t:      return "npm"
    if "dpkg" in t or "apt" in t:      return "apt"
    if "rpm" in t or "yum" in t:       return "yum"
    if "gem" in t or "ruby" in t:      return "gem"
    if "cargo" in t or "rust" in t:    return "cargo"
    if "go" in t:                       return "go"
    # Fallback heuristics
    if pkg_name.startswith("python3-"): return "apt"
    if pkg_name.startswith("lib"):      return "apt"
    return "unknown"


def _fix_command(pkg_mgr: str, pkg_name: str, fixed_version: str | None) -> str:
    ver = f"=={fixed_version}" if fixed_version else ""
    if pkg_mgr == "pip":   return f"pip install --upgrade {pkg_name}{ver}"
    if pkg_mgr == "npm":   return f"npm install {pkg_name}@{fixed_version or 'latest'}"
    if pkg_mgr == "apt":   return f"sudo apt-get install --only-upgrade {pkg_name}"
    if pkg_mgr == "yum":   return f"sudo yum update {pkg_name}"
    if pkg_mgr == "gem":   return f"gem update {pkg_name}"
    if pkg_mgr == "cargo": return f"cargo update {pkg_name}"
    if pkg_mgr == "go":    return f"go get {pkg_name}@latest"
    return f"Update '{pkg_name}' to {fixed_version or 'latest fixed version'} manually"


def get_recommendations(limit: int = 50) -> list[dict]:
    """
    Build remediation recommendations from latest vulnerability scan.
    Returns list of recommendation dicts sorted by severity.
    """
    latest_file = SCANS_DIR / "latest.json"
    if not latest_file.exists():
        return []

    try:
        data = json.loads(latest_file.read_text())
    except Exception:
        return []

    recs: list[dict] = []
    seen_cves: set[str] = set()

    for _dir, scanners in data.get("results", {}).items():
        if not isinstance(scanners, dict):
            continue

        # ── Trivy ─────────────────────────────────────────────────────────────
        trivy = scanners.get("trivy", {})
        for result in (trivy.get("Results", []) if isinstance(trivy, dict) else []):
            pkg_type = result.get("Type", "")
            for v in result.get("Vulnerabilities", []):
                cve = v.get("VulnerabilityID", "")
                if cve in seen_cves:
                    continue
                seen_cves.add(cve)

                sev       = (v.get("Severity") or "low").lower()
                pkg_name  = v.get("PkgName", "unknown")
                fixed_ver = v.get("FixedVersion")
                inst_ver  = v.get("InstalledVersion", "?")
                title     = v.get("Title", "No description")
                url       = v.get("PrimaryURL", "")

                pkg_mgr = _pkg_mgr(pkg_type, pkg_name)
                command = _fix_command(pkg_mgr, pkg_name, fixed_ver)

                recs.append({
                    "cve":              cve,
                    "severity":         sev,
                    "package":          pkg_name,
                    "installed_version": inst_ver,
                    "fixed_version":    fixed_ver or "No fix available yet",
                    "title":            title,
                    "package_manager":  pkg_mgr,
                    "fix_command":      command,
                    "reference":        url,
                    "can_auto_patch":   fixed_ver is not None and pkg_mgr != "unknown",
                    "source":           "trivy",
                })

        # ── OSV  ──────────────────────────────────────────────────────────────
        osv = scanners.get("osv", {})
        if isinstance(osv, dict):
            for v in osv.get("results", []):
                osv_id = v.get("id") or v.get("osv_id", "")
                if osv_id in seen_cves:
                    continue
                seen_cves.add(osv_id)

                pkg_name = v.get("package", {}).get("name", "unknown") if isinstance(v.get("package"), dict) else "unknown"
                recs.append({
                    "cve":              osv_id,
                    "severity":         "medium",
                    "package":          pkg_name,
                    "installed_version": "see OSV",
                    "fixed_version":    "see OSV advisory",
                    "title":            v.get("summary", ""),
                    "package_manager":  "unknown",
                    "fix_command":      f"Update {pkg_name} — see OSV advisory",
                    "reference":        f"https://osv.dev/vulnerability/{osv_id}",
                    "can_auto_patch":   False,
                    "source":           "osv",
                })

    # Sort: critical → high → medium → low
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recs.sort(key=lambda r: order.get(r["severity"], 99))
    return recs[:limit]
