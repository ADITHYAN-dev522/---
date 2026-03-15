export const API_BASE = "http://localhost:8000";

async function request(path: string, options: RequestInit = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) throw new Error(`Backend Error: ${res.status}`);
  return res.json();
}

// Health check
export function backendHealth() {
  return request("/api/health");
}

// Run OSV Scanner
export function runOSV(targetPath: string) {
  return request(`/api/scan/osv?target_path=${encodeURIComponent(targetPath)}`);
}

// Run Trivy Scanner
export function runTrivy(targetPath: string) {
  return request(`/api/scan/trivy?target_path=${encodeURIComponent(targetPath)}`);
}

// Run Semgrep Scanner
export function runSemgrep(targetPath: string) {
  return request(`/api/scan/semgrep?target_path=${encodeURIComponent(targetPath)}`);
}

// Auto-scan results
export function getAutoScanResults() {
  return request("/api/scan/results");
}
