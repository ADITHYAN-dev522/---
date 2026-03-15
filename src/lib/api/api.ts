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
