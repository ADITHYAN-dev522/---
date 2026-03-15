import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ThreatLevelIndicator } from "@/components/dashboard/ThreatLevelIndicator";
import { DetectionChart } from "@/components/dashboard/DetectionChart";
import { RecentAlerts } from "@/components/dashboard/RecentAlerts";
import { StatsCards } from "@/components/dashboard/StatsCards";
import HolographicCard from "@/components/cards/HolographicCard";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, Activity } from "lucide-react";

/* ========================= TYPES ========================= */
type Telemetry = {
  asset?: { hostname?: string; ip_address?: string; asset_id?: string; os?: { system?: string; version?: string } };
  processes?: any[];
  network_connections?: any[];
  recent_files?: any[];
  services?: any[];
  installed_software?: any[];
};

type ThreatEvent = {
  id: string | null;
  timestamp: string;
  type: string;
  scanner: string;
  severity: string;
  title: string;
  details: Record<string, any>;
  status: string;
};

type RiskScore = {
  score: number;
  label: string;
  color: string;
  recommendation: string;
  breakdown: Record<string, number>;
};

const SEV_COLOR: Record<string, string> = {
  critical: "from-red-700/50 to-red-900/40",
  high: "from-orange-600/40 to-orange-900/30",
  medium: "from-yellow-500/30 to-yellow-800/20",
  low: "from-emerald-500/20 to-cyan-600/10",
};

export default function Dashboard() {
  const [backendStatus, setBackendStatus] = useState<"online" | "offline" | "checking">("checking");
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [threatEvents, setThreatEvents] = useState<ThreatEvent[]>([]);
  const [riskScore, setRiskScore] = useState<RiskScore | null>(null);

  /* ── Backend health check ── */
  useEffect(() => {
    fetch("http://localhost:8000/api/health")
      .then(r => r.ok ? setBackendStatus("online") : setBackendStatus("offline"))
      .catch(() => setBackendStatus("offline"));
  }, []);

  /* ── Telemetry ── */
  useEffect(() => {
    fetch("http://localhost:8000/api/telemetry/latest", { cache: "no-store" })
      .then(r => r.json()).then(setTelemetry).catch(() => setTelemetry(null));
  }, []);

  /* ── Real threat events from ThreatSentinel ── */
  useEffect(() => {
    fetch("http://localhost:8000/api/threat-sentinel/events?limit=6", { cache: "no-store" })
      .then(r => r.json()).then(d => setThreatEvents(Array.isArray(d) ? d : [])).catch(() => setThreatEvents([]));
  }, []);

  /* ── Risk score ── */
  useEffect(() => {
    fetch("http://localhost:8000/api/risk/score", { cache: "no-store" })
      .then(r => r.json()).then(setRiskScore).catch(() => setRiskScore(null));
  }, []);

  const normalizedTelemetry = telemetry && {
    asset: telemetry.asset ?? {},
    processes: telemetry.processes ?? [],
    network_connections: telemetry.network_connections ?? [],
    recent_files: telemetry.recent_files ?? [],
    services: telemetry.services ?? [],
    installed_software: telemetry.installed_software ?? [],
  };

  const statusColor = { checking: "bg-yellow-500", online: "bg-green-500", offline: "bg-red-600" }[backendStatus];
  const statusText = { checking: "Checking backend…", online: "Connected to backend", offline: "Backend offline" }[backendStatus];

  return (
    <div className="space-y-6">
      {/* ── Backend status ── */}
      <div className="flex items-center gap-3 p-3 border rounded-xl bg-card shadow-md w-fit">
        <div className={`h-3 w-3 rounded-full ${statusColor}`} />
        <p className="text-sm font-medium">{statusText}</p>
        {riskScore && (
          <Badge style={{ backgroundColor: riskScore.color }} className="ml-2 font-bold">
            Risk: {riskScore.label} ({riskScore.score}/100)
          </Badge>
        )}
      </div>

      {/* ── Header ── */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-[#9D4EDD] via-[#FF1744] to-[#00D9FF] bg-clip-text text-transparent">
          Security Dashboard
        </h1>
        <p className="text-muted-foreground">Real-time monitoring and threat intelligence overview</p>
      </motion.div>

      {/* ── Risk score banner ── */}
      {riskScore && (
        <motion.div
          initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
          className="p-4 rounded-xl border"
          style={{ borderColor: riskScore.color + "50", background: riskScore.color + "10" }}
        >
          <div className="flex items-center gap-3">
            <Activity className="h-5 w-5" style={{ color: riskScore.color }} />
            <div>
              <p className="font-semibold" style={{ color: riskScore.color }}>
                Platform Risk: {riskScore.label} — {riskScore.score}/100
              </p>
              <p className="text-sm text-muted-foreground">{riskScore.recommendation}</p>
            </div>
          </div>
        </motion.div>
      )}

      <StatsCards />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <ThreatLevelIndicator level={riskScore ? riskScore.label.toLowerCase() as any : "low"} />
        </div>
        <div className="lg:col-span-2">
          <DetectionChart />
        </div>
      </div>

      {/* ── Live threat events from ThreatSentinel (replaces hardcoded cards) ── */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-2">
        <h2 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <ShieldAlert className="h-6 w-6 text-red-400" />
          Live Threat Events
        </h2>
        <p className="text-muted-foreground">Real detections from ClamAV · YARA · Trivy · Wazuh</p>
      </motion.div>

      {threatEvents.length === 0 ? (
        <div className="p-6 rounded-xl border border-border bg-card/30 text-center">
          <p className="text-muted-foreground">
            {backendStatus === "offline"
              ? "Backend is offline — start the FastAPI server to see live events."
              : "No threat events detected. System appears clean or scan is still running."}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {threatEvents.map((evt, i) => (
            <motion.div key={i} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
              <HolographicCard
                title={evt.title}
                severity={evt.severity as any}
                frontData={{
                  detections: 1,
                  affected: evt.details?.path || evt.details?.cve || evt.scanner,
                  status: evt.status.charAt(0).toUpperCase() + evt.status.slice(1),
                }}
                backData={{
                  source: evt.scanner,
                  target: evt.type.replace(/_/g, " "),
                  vector: new Date(evt.timestamp).toLocaleString(),
                  mitigation: evt.details?.threat_label || evt.details?.title || "Investigate immediately",
                }}
              />
            </motion.div>
          ))}
        </div>
      )}

      {/* ── Telemetry overview ── */}
      {normalizedTelemetry && (
        <>
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-2">
            <h2 className="text-2xl font-semibold tracking-tight">Asset & Telemetry Overview</h2>
            <p className="text-muted-foreground">Snapshot-based host visibility and system activity</p>
          </motion.div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <HolographicCard title="Asset Identity" severity="low"
              frontData={{ detections: 1, affected: normalizedTelemetry.asset.hostname ?? "Unknown Host", status: normalizedTelemetry.asset.os?.system ?? "Unknown OS" }}
              backData={{ source: normalizedTelemetry.asset.ip_address ?? "N/A", target: normalizedTelemetry.asset.asset_id ?? "N/A", vector: normalizedTelemetry.asset.os?.version ?? "N/A", mitigation: "Asset inventory baseline established" }} />
            <HolographicCard title="Running Processes" severity="medium"
              frontData={{ detections: normalizedTelemetry.processes.length, affected: "Host", status: "Snapshot Collected" }}
              backData={{ source: "ps", target: "System Processes", vector: "Process enumeration", mitigation: "Investigate unknown or long-running processes" }} />
            <HolographicCard title="Network Connections" severity="medium"
              frontData={{ detections: normalizedTelemetry.network_connections.length, affected: "Network Stack", status: "Observed" }}
              backData={{ source: "ss", target: "Active sockets", vector: "Network telemetry", mitigation: "Review unexpected outbound connections" }} />
            <HolographicCard title="Recent File Activity" severity="low"
              frontData={{ detections: normalizedTelemetry.recent_files.length, affected: "Filesystem", status: "Last 24 Hours" }}
              backData={{ source: "find", target: "User directories", vector: "File modification", mitigation: "Validate unexpected file changes" }} />
            <HolographicCard title="Running Services" severity="low"
              frontData={{ detections: normalizedTelemetry.services.length, affected: "System Services", status: "Active" }}
              backData={{ source: "systemctl", target: "Service Manager", vector: "Service inventory", mitigation: "Disable unused or unknown services" }} />
            <HolographicCard title="Installed Software" severity="low"
              frontData={{ detections: normalizedTelemetry.installed_software.length, affected: "Host", status: "Inventory" }}
              backData={{ source: "dpkg", target: "Installed packages", vector: "Software inventory", mitigation: "Remove outdated or unnecessary software" }} />
          </div>
        </>
      )}

      <RecentAlerts />
    </div>
  );
}
