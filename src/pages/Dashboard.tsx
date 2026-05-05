import { useEffect, useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { StatsCards } from "@/components/dashboard/StatsCards";
import { DetectionChart } from "@/components/dashboard/DetectionChart";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ShieldAlert, Activity, AlertTriangle, Clock,
  RotateCw, Wifi, WifiOff, TrendingUp, Radar, FileDown, Loader2,
} from "lucide-react";

/* ─── Types ── */
type ThreatEvent = {
  id: string | null; timestamp: string; type: string;
  scanner: string; severity: string; title: string; details: Record<string, any>; status: string;
};
type RiskScore = { score: number; label: string; color: string; recommendation: string; breakdown: Record<string, number> };
type Telemetry = { asset?: { hostname?: string; ip_address?: string; os?: { system?: string } } };

const SEV: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#10b981",
};
const SEV_BG: Record<string, string> = {
  critical: "rgba(239,68,68,0.08)", high: "rgba(249,115,22,0.07)",
  medium: "rgba(234,179,8,0.06)", low: "rgba(16,185,129,0.05)",
};

/* ─── Animated Number ── */
function AnimNum({ value, suffix = "" }: { value: number; suffix?: string }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let frame: number;
    const start = performance.now();
    const dur = 1200;
    const animate = (now: number) => {
      const progress = Math.min((now - start) / dur, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(eased * value));
      if (progress < 1) frame = requestAnimationFrame(animate);
    };
    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [value]);
  return <>{display}{suffix}</>;
}

/* ─── Risk Gauge with radar sweep ── */
function RiskGauge({ score, label, color }: { score: number; label: string; color: string }) {
  const r = 68, cx = 84, cy = 84;
  const circumference = Math.PI * r;
  const offset = circumference - (score / 100) * circumference;

  return (
    <Card className="glass-elevated p-6 flex flex-col items-center relative overflow-hidden group">
      {/* Background glow */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
        style={{ background: `radial-gradient(circle at 50% 80%, ${color}12, transparent 70%)` }}
      />
      <p className="text-xs text-muted-foreground font-medium mb-3 flex items-center gap-1.5 relative z-10">
        <Radar className="h-3.5 w-3.5 text-primary/50" />
        Platform Risk Score
      </p>
      <div className="relative w-[168px] h-[96px]">
        <svg width="168" height="96" viewBox="0 0 168 96">
          {/* Track */}
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none" stroke="hsl(225 16% 12%)" strokeWidth="8" strokeLinecap="round"
          />
          {/* Fill */}
          <motion.path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.6, ease: [0.22, 1, 0.36, 1] }}
            style={{ filter: `drop-shadow(0 0 8px ${color}60)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-0.5">
          <span className="text-3xl font-bold tabular-nums" style={{ color }}>
            <AnimNum value={score} />
          </span>
          <span className="text-[10px] text-muted-foreground/60 font-mono">/ 100</span>
        </div>
      </div>
      <motion.span
        className="mt-3 text-[11px] font-bold px-3 py-1 rounded-full relative z-10"
        style={{ color, background: `${color}15`, border: `1px solid ${color}30` }}
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1 }}
      >
        {label}
      </motion.span>
    </Card>
  );
}

/* ─── Scanner breakdown mini-bar ── */
function ScannerBreakdown({ events }: { events: ThreatEvent[] }) {
  const scanners = ["clamav", "yara", "trivy", "wazuh", "semgrep", "nuclei", "bandit"];
  const counts = scanners.map(s => ({
    name: s.toUpperCase(),
    count: events.filter(e => e.scanner?.toLowerCase().includes(s)).length,
  })).sort((a, b) => b.count - a.count);
  const max = Math.max(...counts.map(c => c.count), 1);
  const colors = ["#00d4ff", "#ef4444", "#eab308", "#8b5cf6", "#10b981"];

  return (
    <Card className="glass-elevated p-6">
      <p className="text-xs font-semibold mb-4 flex items-center gap-2">
        <TrendingUp className="h-3.5 w-3.5 text-primary/60" /> Detections by Scanner
      </p>
      <div className="space-y-3">
        {counts.map((c, i) => (
          <div key={c.name} className="flex items-center gap-3">
            <span className="text-[10px] font-mono w-14 text-muted-foreground/70">{c.name}</span>
            <div className="flex-1 h-[6px] rounded-full bg-muted/50 overflow-hidden">
              <motion.div
                className="h-full rounded-full"
                style={{
                  background: `linear-gradient(90deg, ${colors[i % colors.length]}, ${colors[i % colors.length]}80)`,
                  boxShadow: `0 0 8px ${colors[i % colors.length]}30`,
                }}
                initial={{ width: 0 }}
                animate={{ width: `${(c.count / max) * 100}%` }}
                transition={{ delay: i * 0.1, duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
              />
            </div>
            <span className="text-[10px] text-muted-foreground/60 w-6 text-right font-mono tabular-nums">{c.count}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

/* ─── Live events table ── */
function LiveEventsFeed({ events, loading, onRefresh }: { events: ThreatEvent[]; loading: boolean; onRefresh: () => void }) {
  return (
    <Card className="glass-elevated overflow-hidden">
      <div className="p-4 border-b border-border/30 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg" style={{ background: "rgba(239,68,68,0.1)" }}>
            <ShieldAlert className="h-4 w-4 text-red-400" />
          </div>
          <h2 className="text-sm font-semibold">Live Threat Events</h2>
          <Badge variant="outline" className="text-[10px] font-mono ml-1 border-border/40">{events.length}</Badge>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="p-1.5 rounded-lg hover:bg-white/5 transition-colors disabled:opacity-40"
        >
          <RotateCw className={`h-3.5 w-3.5 text-muted-foreground ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      <div className="divide-y divide-border/20 max-h-[420px] overflow-y-auto">
        <AnimatePresence>
          {events.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-14 text-center">
              <ShieldAlert className="h-10 w-10 text-primary/10" />
              <p className="text-sm text-muted-foreground/60">
                {loading ? "Loading events…" : "No threat events — system appears clean."}
              </p>
            </div>
          ) : (
            events.map((e, i) => {
              const col = SEV[e.severity] ?? "#64748b";
              const bg  = SEV_BG[e.severity]  ?? "transparent";
              const Icon = e.severity === "critical" ? ShieldAlert : e.severity === "high" ? AlertTriangle : Activity;
              return (
                <motion.div
                  key={`${e.id}-${i}`}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.02 }}
                  className="flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors group"
                  style={{ borderLeft: `2px solid ${col}`, background: bg }}
                >
                  <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: col }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-[13px] font-medium truncate">{e.title}</p>
                    <p className="text-[10px] text-muted-foreground/60 font-mono">
                      {e.scanner} · {e.details?.cve || e.details?.path?.split("/").pop() || e.type.replace(/_/g, " ")}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span
                      className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                      style={{ color: col, background: `${col}15`, border: `1px solid ${col}25` }}
                    >
                      {e.severity.toUpperCase()}
                    </span>
                    <span className="text-[9px] text-muted-foreground/50 font-mono flex items-center gap-0.5">
                      <Clock className="h-2.5 w-2.5" />
                      {new Date(e.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                    </span>
                    <Badge variant={e.status === "open" ? "destructive" : "secondary"} className="text-[9px] h-4">
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
  const statusColors = { checking: "#eab308", online: "#10b981", offline: "#ef4444" };
  const statusCol = statusColors[backendStatus];

  return (
    <div className="space-y-5">
      {/* ── Top bar: status + asset info + report download ── */}
      <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-2.5 flex-wrap">
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-full glass-effect text-[11px] font-mono"
            style={{ borderColor: `${statusCol}25` }}
          >
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-60" style={{ background: statusCol }} />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5" style={{ background: statusCol }} />
            </span>
            <span style={{ color: statusCol }}>
              {backendStatus === "checking" ? "Connecting…" : backendStatus === "online" ? "Backend Online" : "Backend Offline"}
            </span>
            {backendStatus === "online" ? <Wifi className="h-3 w-3" style={{ color: statusCol }} /> : <WifiOff className="h-3 w-3" style={{ color: statusCol }} />}
          </div>
          {asset?.hostname && (
            <span className="text-[10px] text-muted-foreground/50 font-mono px-3 py-1.5 rounded-full glass-effect">
              🖥 {asset.hostname} · {asset.ip_address} · {asset.os?.system}
            </span>
          )}
        </div>

        <button
          onClick={() => window.open("/api/report/generate", "_blank")}
          className="inline-flex items-center gap-2 px-4 py-1.5 rounded-lg text-[11px] font-semibold transition-all hover:-translate-y-0.5"
          style={{ background: "rgba(0,212,255,0.1)", color: "#00d4ff", border: "1px solid rgba(0,212,255,0.2)" }}
        >
          <FileDown className="w-3.5 h-3.5" />
          Download PDF Report
        </button>
      </motion.div>

      {/* ── Page header ── */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{
            background: "linear-gradient(135deg, #00d4ff, #38bdf8, #10b981)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}
        >
          Security Dashboard
        </h1>
        <p className="text-muted-foreground/60 text-sm mt-0.5">Real-time threat monitoring and system health overview</p>
      </motion.div>

      {/* ── Stats row ── */}
      <StatsCards />

      {/* ── Risk gauge + scanner breakdown + chart ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          {riskScore ? (
            <RiskGauge score={riskScore.score} label={riskScore.label} color={riskScore.color} />
          ) : (
            <Card className="glass-elevated p-6 flex items-center justify-center h-full min-h-[180px]">
              <div className="flex flex-col items-center gap-2">
                <Radar className="h-8 w-8 text-primary/15 animate-pulse" />
                <p className="text-xs text-muted-foreground/50">Loading risk score…</p>
              </div>
            </Card>
          )}
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <ScannerBreakdown events={threatEvents} />
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="md:col-span-1">
          {riskScore?.breakdown && (
            <Card className="glass-elevated p-6 h-full">
              <p className="text-xs font-semibold mb-4">Risk Breakdown</p>
              <div className="space-y-3">
                {Object.entries(riskScore.breakdown).map(([k, v], i) => (
                  <div key={k} className="flex items-center gap-3">
                    <span className="text-[10px] text-muted-foreground/60 capitalize w-20 truncate">{k.replace(/_/g," ")}</span>
                    <div className="flex-1 h-[5px] rounded-full bg-muted/40 overflow-hidden">
                      <motion.div
                        className="h-full rounded-full"
                        style={{ background: "linear-gradient(90deg, #00d4ff, #8b5cf6)" }}
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.min((v / 20) * 100, 100)}%` }}
                        transition={{ delay: i * 0.1, duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
                      />
                    </div>
                    <span className="text-[10px] font-mono text-primary/60 w-6 text-right tabular-nums">{v}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </motion.div>
      </div>

      {/* ── Chart ── */}
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        <DetectionChart />
      </motion.div>

      {/* ── Live event table ── */}
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
        <LiveEventsFeed events={threatEvents} loading={loading} onRefresh={fetchAll} />
      </motion.div>
    </div>
  );
}
