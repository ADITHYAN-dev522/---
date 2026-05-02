import { useEffect, useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { StatsCards } from "@/components/dashboard/StatsCards";
import { DetectionChart } from "@/components/dashboard/DetectionChart";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ShieldAlert, Activity, AlertTriangle, Clock,
  RotateCw, Wifi, WifiOff, TrendingUp,
} from "lucide-react";

/* ─── Types ── */
type ThreatEvent = {
  id: string | null; timestamp: string; type: string;
  scanner: string; severity: string; title: string; details: Record<string, any>; status: string;
};
type RiskScore = { score: number; label: string; color: string; recommendation: string; breakdown: Record<string, number> };
type Telemetry = { asset?: { hostname?: string; ip_address?: string; os?: { system?: string } } };

const SEV: Record<string, string> = {
  critical: "#F87171", high: "#FB923C", medium: "#FBBF24", low: "#34D399",
};
const SEV_BG: Record<string, string> = {
  critical: "rgba(248,113,113,0.10)", high: "rgba(251,146,60,0.09)",
  medium: "rgba(251,191,36,0.08)", low: "rgba(52,211,153,0.07)",
};

/* ─── Risk Gauge ── */
function RiskGauge({ score, label, color }: { score: number; label: string; color: string }) {
  const r = 64, cx = 80, cy = 80;
  const circumference = Math.PI * r;          // half circle
  const offset = circumference - (score / 100) * circumference;

  return (
    <Card className="glass-effect border-primary/20 p-6 flex flex-col items-center">
      <p className="text-sm text-muted-foreground font-medium mb-4">Platform Risk Score</p>
      <div className="relative w-40 h-24">
        <svg width="160" height="100" viewBox="0 0 160 100">
          {/* Track */}
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none" stroke="hsl(220 14% 16%)" strokeWidth="10" strokeLinecap="round"
          />
          {/* Fill */}
          <motion.path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.4, ease: "easeOut" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-1">
          <motion.span
            className="text-3xl font-bold"
            style={{ color }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.8 }}
          >
            {score}
          </motion.span>
          <span className="text-xs text-muted-foreground">/ 100</span>
        </div>
      </div>
      <span
        className="mt-3 text-sm font-bold px-3 py-1 rounded-full"
        style={{ color, background: `${color}20`, border: `1px solid ${color}40` }}
      >
        {label}
      </span>
    </Card>
  );
}

/* ─── Scanner breakdown mini-bar ── */
function ScannerBreakdown({ events }: { events: ThreatEvent[] }) {
  const scanners = ["clamav", "yara", "trivy", "wazuh", "semgrep"];
  const counts = scanners.map(s => ({
    name: s.toUpperCase(),
    count: events.filter(e => e.scanner?.toLowerCase().includes(s)).length,
  })).sort((a, b) => b.count - a.count);
  const max = Math.max(...counts.map(c => c.count), 1);
  const colors = ["#22D3EE", "#F87171", "#FBBF24", "#818CF8", "#34D399"];

  return (
    <Card className="glass-effect border-primary/20 p-6">
      <p className="text-sm font-semibold mb-4 flex items-center gap-2">
        <TrendingUp className="h-4 w-4 text-primary" /> Detections by Scanner
      </p>
      <div className="space-y-3">
        {counts.map((c, i) => (
          <div key={c.name} className="flex items-center gap-3">
            <span className="text-xs font-mono w-16 text-muted-foreground">{c.name}</span>
            <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
              <motion.div
                className="h-full rounded-full"
                style={{ background: colors[i % colors.length] }}
                initial={{ width: 0 }}
                animate={{ width: `${(c.count / max) * 100}%` }}
                transition={{ delay: i * 0.1, duration: 0.8, ease: "easeOut" }}
              />
            </div>
            <span className="text-xs text-muted-foreground w-6 text-right">{c.count}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

/* ─── Live events table ── */
function LiveEventsFeed({ events, loading, onRefresh }: { events: ThreatEvent[]; loading: boolean; onRefresh: () => void }) {
  return (
    <Card className="glass-effect border-primary/20">
      <div className="p-5 border-b border-border/60 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-primary" />
          <h2 className="text-base font-semibold">Live Threat Events</h2>
          <Badge variant="outline" className="text-xs font-mono ml-1">{events.length}</Badge>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="p-1.5 rounded-lg border border-border/60 hover:border-primary/30 hover:bg-primary/5 transition-colors disabled:opacity-40"
        >
          <RotateCw className={`h-3.5 w-3.5 text-muted-foreground ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      <div className="divide-y divide-border/40 max-h-[420px] overflow-y-auto">
        <AnimatePresence>
          {events.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-14 text-center">
              <ShieldAlert className="h-10 w-10 text-primary/15" />
              <p className="text-sm text-muted-foreground">
                {loading ? "Loading events…" : "No threat events — system appears clean."}
              </p>
            </div>
          ) : (
            events.map((e, i) => {
              const col = SEV[e.severity] ?? "#94A3B8";
              const bg  = SEV_BG[e.severity]  ?? "transparent";
              const Icon = e.severity === "critical" ? ShieldAlert : e.severity === "high" ? AlertTriangle : Activity;
              return (
                <motion.div
                  key={`${e.id}-${i}`}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.03 }}
                  className="flex items-center gap-4 px-5 py-3.5 hover:brightness-110 transition-all group"
                  style={{ borderLeft: `3px solid ${col}`, background: bg }}
                >
                  <Icon className="h-4 w-4 shrink-0" style={{ color: col }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{e.title}</p>
                    <p className="text-xs text-muted-foreground font-mono">
                      {e.scanner} · {e.details?.cve || e.details?.path?.split("/").pop() || e.type.replace(/_/g, " ")}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span
                      className="text-[10px] font-bold px-2 py-0.5 rounded"
                      style={{ color: col, background: `${col}20`, border: `1px solid ${col}30` }}
                    >
                      {e.severity.toUpperCase()}
                    </span>
                    <span className="text-[10px] text-muted-foreground font-mono flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(e.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                    </span>
                    <Badge variant={e.status === "open" ? "destructive" : "secondary"} className="text-[10px]">
                      {e.status}
                    </Badge>
                  </div>
                </motion.div>
              );
            })
          )}
        </AnimatePresence>
      </div>
    </Card>
  );
}

/* ─── Main Page ── */
export default function Dashboard() {
  const [riskScore,    setRiskScore]    = useState<RiskScore | null>(null);
  const [telemetry,    setTelemetry]    = useState<Telemetry | null>(null);
  const [threatEvents, setThreatEvents] = useState<ThreatEvent[]>([]);
  const [backendStatus, setBackendStatus] = useState<"online"|"offline"|"checking">("checking");
  const [loading, setLoading] = useState(false);
  const mounted = useRef(true);

  const fetchAll = async () => {
    setLoading(true);
    const safeJson = (r: Response) => r.ok ? r.json() : Promise.reject(r.status);
    try {
      const [health, tel, events, risk] = await Promise.all([
        fetch("/api/health").then(r => r.ok ? "online" : "offline"),
        fetch("/api/telemetry/latest",              { cache: "no-store" }).then(safeJson).catch(() => null),
        fetch("/api/threat-sentinel/events?limit=50", { cache: "no-store" }).then(safeJson).catch(() => []),
        fetch("/api/risk/score",                    { cache: "no-store" }).then(safeJson).catch(() => null),
      ]);
      if (!mounted.current) return;
      setBackendStatus(health as "online" | "offline");
      setTelemetry(tel ?? null);
      setThreatEvents(Array.isArray(events) ? events : []);
      setRiskScore(risk ?? null);
    } catch {
      setBackendStatus("offline");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    mounted.current = true;
    fetchAll();
    return () => { mounted.current = false; };
  }, []);

  const asset = telemetry?.asset;
  const statusColors = { checking: "#FBBF24", online: "#34D399", offline: "#F87171" };
  const statusCol = statusColors[backendStatus];

  return (
    <div className="space-y-6">
      {/* ── Top bar: status + asset info ── */}
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border glass-effect" style={{ borderColor: `${statusCol}30` }}>
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ background: statusCol }} />
            <span className="relative inline-flex rounded-full h-2 w-2" style={{ background: statusCol }} />
          </span>
          <span className="text-xs font-mono" style={{ color: statusCol }}>
            {backendStatus === "checking" ? "Connecting…" : backendStatus === "online" ? "Backend Online" : "Backend Offline"}
          </span>
          {backendStatus === "online" ? <Wifi className="h-3 w-3" style={{ color: statusCol }} /> : <WifiOff className="h-3 w-3" style={{ color: statusCol }} />}
        </div>
        {asset?.hostname && (
          <span className="text-xs text-muted-foreground font-mono px-3 py-1.5 rounded-full border border-border/60 glass-effect">
            🖥 {asset.hostname} · {asset.ip_address} · {asset.os?.system}
          </span>
        )}
      </motion.div>

      {/* ── Page header ── */}
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-[#22D3EE] via-[#38BDF8] to-[#34D399] bg-clip-text text-transparent">
          Security Dashboard
        </h1>
        <p className="text-muted-foreground text-sm mt-1">Real-time threat monitoring and system health overview</p>
      </motion.div>

      {/* ── Stats row ── */}
      <StatsCards />

      {/* ── Risk gauge + scanner breakdown + chart ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          {riskScore ? (
            <RiskGauge score={riskScore.score} label={riskScore.label} color={riskScore.color} />
          ) : (
            <Card className="glass-effect border-primary/20 p-6 flex items-center justify-center h-full min-h-[180px]">
              <p className="text-sm text-muted-foreground">Loading risk score…</p>
            </Card>
          )}
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <ScannerBreakdown events={threatEvents} />
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="md:col-span-1">
          {riskScore?.breakdown && (
            <Card className="glass-effect border-primary/20 p-6 h-full">
              <p className="text-sm font-semibold mb-4">Risk Breakdown</p>
              <div className="space-y-3">
                {Object.entries(riskScore.breakdown).map(([k, v], i) => (
                  <div key={k} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground capitalize w-20 truncate">{k.replace(/_/g," ")}</span>
                    <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                      <motion.div
                        className="h-full rounded-full bg-gradient-to-r from-primary to-secondary"
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.min((v / 20) * 100, 100)}%` }}
                        transition={{ delay: i * 0.1, duration: 0.7 }}
                      />
                    </div>
                    <span className="text-xs font-mono text-primary w-6 text-right">{v}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </motion.div>
      </div>

      {/* ── Chart ── */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        <DetectionChart />
      </motion.div>

      {/* ── Live event table ── */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
        <LiveEventsFeed events={threatEvents} loading={loading} onRefresh={fetchAll} />
      </motion.div>
    </div>
  );
}
