import { motion, AnimatePresence } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ShieldAlert, RefreshCw, WifiOff, AlertTriangle,
  ExternalLink, Clock,
} from "lucide-react";
import { useEffect, useMemo, useState, useCallback } from "react";

/* ─── Types ─────────────────────────────────────────────────────────────── */
type WazuhAlert = {
  id?: string;
  timestamp: string;
  severity: number;
  rule: string;
  rule_id?: string;
  groups?: string[];
  agent: string;
  location?: string;
  mitre?: { id?: string[]; tactic?: string[]; technique?: string[] };
  source: "wazuh";
};

/* ─── Helpers ────────────────────────────────────────────────────────────── */
function sevLabel(n: number): string {
  if (n >= 10) return "CRITICAL";
  if (n >= 7)  return "HIGH";
  if (n >= 5)  return "MEDIUM";
  if (n >= 3)  return "LOW";
  return "INFO";
}
function sevColor(n: number): string {
  if (n >= 10) return "#ef4444";
  if (n >= 7)  return "#f97316";
  if (n >= 5)  return "#eab308";
  if (n >= 3)  return "#10b981";
  return "#64748b";
}
function sevBg(n: number): string {
  if (n >= 10) return "rgba(239,68,68,0.06)";
  if (n >= 7)  return "rgba(249,115,22,0.06)";
  if (n >= 5)  return "rgba(234,179,8,0.05)";
  if (n >= 3)  return "rgba(16,185,129,0.04)";
  return "rgba(100,116,139,0.04)";
}

const BUCKETS = [
  { label: "CRITICAL", min: 10, max: 15, color: "#ef4444" },
  { label: "HIGH",     min: 7,  max: 9,  color: "#f97316" },
  { label: "MEDIUM",   min: 5,  max: 6,  color: "#eab308" },
  { label: "LOW",      min: 3,  max: 4,  color: "#10b981" },
  { label: "INFO",     min: 0,  max: 2,  color: "#64748b" },
];

/* ─── Alert Card ─────────────────────────────────────────────────────────── */
function AlertCard({ alert, index }: { alert: WazuhAlert; index: number }) {
  const col = sevColor(alert.severity);
  const bg  = sevBg(alert.severity);
  const techniques = alert.mitre?.technique ?? [];

  return (
    <motion.div
      key={alert.id ?? index}
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.02 }}
      className="rounded-xl overflow-hidden border-l-[3px] border"
      style={{ borderLeftColor: col, borderColor: `${col}18`, background: bg }}
    >
      <div className="p-4">
        {/* Top row */}
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span
              className="text-[10px] font-bold px-1.5 py-0.5 rounded"
              style={{ color: col, background: `${col}15`, border: `1px solid ${col}25` }}
            >
              {sevLabel(alert.severity)} / {alert.severity}
            </span>
            {alert.rule_id && (
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/[0.03] text-muted-foreground/40 border border-white/[0.06]">
                Rule #{alert.rule_id}
              </span>
            )}
            {(alert.groups ?? []).slice(0, 2).map(g => (
              <span key={g} className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.03] text-muted-foreground/40 font-mono border border-white/[0.06]">
                {g}
              </span>
            ))}
          </div>
          <div className="flex items-center gap-1 text-[10px] text-muted-foreground/40 shrink-0">
            <Clock className="h-2.5 w-2.5" />
            {new Date(alert.timestamp).toLocaleTimeString()}
          </div>
        </div>

        {/* Rule description */}
        <p className="text-[13px] font-medium leading-snug mb-2">
          {alert.rule || "Unknown Rule"}
        </p>

        {/* Agent + Location */}
        <div className="flex flex-wrap gap-4 text-[10px] text-muted-foreground/50 mb-2">
          {alert.agent && (
            <span>Agent: <strong className="text-foreground/70">{alert.agent}</strong></span>
          )}
          {alert.location && (
            <span className="truncate max-w-xs">
              Location: <code className="text-muted-foreground/50 text-[9px]">{alert.location}</code>
            </span>
          )}
        </div>

        {/* MITRE ATT&CK */}
        {techniques.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {techniques.slice(0, 4).map(t => (
              <a
                key={t}
                href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}`}
                target="_blank"
                rel="noreferrer"
                className="text-[9px] px-2 py-0.5 rounded border font-mono flex items-center gap-1 hover:opacity-80 transition-opacity"
                style={{ color: "#f97316", borderColor: "#f9731625", background: "rgba(249,115,22,0.06)" }}
              >
                MITRE {t} <ExternalLink className="h-2.5 w-2.5" />
              </a>
            ))}
          </div>
        )}
      </div>
    </motion.div>
  );
}

/* ─── Main Page ──────────────────────────────────────────────────────────── */
export default function Intelligence() {
  const [alerts, setAlerts]         = useState<WazuhAlert[]>([]);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [now, setNow]               = useState(Date.now());

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/threat-intel/wazuh/alerts", { cache: "no-store" });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setAlerts(Array.isArray(data) ? data : []);
      setLastUpdated(Date.now());
    } catch (e: any) {
      setError(e.message || "Failed to connect to Wazuh");
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const id = setInterval(fetchAlerts, 30_000);
    return () => clearInterval(id);
  }, [fetchAlerts]);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const buckets = useMemo(() => {
    return BUCKETS.map(b => ({
      ...b,
      count: alerts.filter(a => a.severity >= b.min && a.severity <= b.max).length,
    }));
  }, [alerts]);

  const secondsAgo = lastUpdated ? Math.floor((now - lastUpdated) / 1000) : null;

  return (
    <div className="space-y-5">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-1">
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{
            background: "linear-gradient(135deg, #00d4ff, #8b5cf6, #ef4444)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}
        >
          Threat Intelligence
        </h1>
        <p className="text-sm text-muted-foreground/60">Real-time host-based security alerts from Wazuh SIEM</p>
      </motion.div>

      {/* Status bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 text-xs">
          {loading
            ? <RefreshCw className="h-3 w-3 text-yellow-400 animate-spin" />
            : error
              ? <WifiOff className="h-3 w-3 text-red-400" />
              : <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse inline-block" />}
          <span className={`text-[11px] font-medium ${error ? "text-red-400" : "text-emerald-400"}`}>
            {loading ? "Fetching…" : error ? "Wazuh Unreachable" : "Live Wazuh Feed"}
          </span>
          {secondsAgo !== null && !loading && !error && (
            <span className="text-[10px] text-muted-foreground/40">• Updated {secondsAgo}s ago</span>
          )}
        </div>
        <button
          onClick={fetchAlerts}
          disabled={loading}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs glass-effect hover:bg-white/5 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Error banner */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
            className="flex items-start gap-3 p-4 rounded-xl border border-red-500/15 bg-red-900/5"
          >
            <AlertTriangle className="h-4 w-4 text-red-400/80 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold text-red-300/80">Could not reach Wazuh Indexer</p>
              <p className="text-[10px] text-red-400/50 mt-0.5">
                {error} — Ensure <code className="font-mono text-red-300/60">WAZUH_INDEXER_PASSWORD</code> is set and the Wazuh stack is running on the Kali VM.
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Severity breakdown cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2.5">
        {buckets.map((b, i) => (
          <motion.div
            key={b.label}
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.04 }}
            whileHover={{ y: -2 }}
          >
            <Card
              className="glass-elevated p-4 relative overflow-hidden group cursor-default"
              style={{ borderColor: `${b.color}15` }}
            >
              <div
                className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
                style={{ background: `linear-gradient(135deg, ${b.color}08, transparent)` }}
              />
              <p className="text-[9px] font-bold tracking-widest mb-1 relative z-10" style={{ color: b.color }}>
                {b.label}
              </p>
              <p className="text-2xl font-bold relative z-10">{b.count}</p>
              <p className="text-[9px] text-muted-foreground/30 mt-0.5 relative z-10">alerts</p>
              <div className="absolute bottom-0 left-0 right-0 h-[1px]" style={{ background: `linear-gradient(90deg, transparent, ${b.color}25, transparent)` }} />
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Alert feed */}
      <Card className="glass-elevated p-5" style={{ borderColor: "#8b5cf615" }}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-red-400/70" />
            Live Security Alerts
            {alerts.length > 0 && (
              <Badge variant="outline" className="ml-1 text-[10px] font-mono border-border/30">{alerts.length}</Badge>
            )}
          </h2>
        </div>

        {alerts.length === 0 && !loading ? (
          <div className="flex flex-col items-center gap-3 py-14 text-center">
            {error ? (
              <>
                <WifiOff className="h-10 w-10 text-red-400/15" />
                <p className="text-sm text-muted-foreground/40 max-w-sm">
                  Wazuh indexer is unreachable. Start the Wazuh stack to see live alerts.
                </p>
              </>
            ) : (
              <>
                <ShieldAlert className="h-10 w-10 text-emerald-500/15" />
                <p className="text-sm text-muted-foreground/40">No active Wazuh alerts — system appears calm.</p>
              </>
            )}
          </div>
        ) : (
          <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
            <AnimatePresence>
              {alerts.map((alert, i) => (
                <AlertCard key={alert.id ?? i} alert={alert} index={i} />
              ))}
            </AnimatePresence>
          </div>
        )}
      </Card>
    </div>
  );
}
