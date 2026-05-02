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
  if (n >= 10) return "#FF1744";
  if (n >= 7)  return "#FF6D00";
  if (n >= 5)  return "#FFC107";
  if (n >= 3)  return "#00E676";
  return "#9E9E9E";
}
function sevBg(n: number): string {
  if (n >= 10) return "rgba(255,23,68,0.10)";
  if (n >= 7)  return "rgba(255,109,0,0.10)";
  if (n >= 5)  return "rgba(255,193,7,0.08)";
  if (n >= 3)  return "rgba(0,230,118,0.07)";
  return "rgba(158,158,158,0.07)";
}

const BUCKETS = [
  { label: "CRITICAL", min: 10, max: 15, color: "#FF1744" },
  { label: "HIGH",     min: 7,  max: 9,  color: "#FF6D00" },
  { label: "MEDIUM",   min: 5,  max: 6,  color: "#FFC107" },
  { label: "LOW",      min: 3,  max: 4,  color: "#00E676" },
  { label: "INFO",     min: 0,  max: 2,  color: "#9E9E9E" },
];

/* ─── Alert Card ─────────────────────────────────────────────────────────── */
function AlertCard({ alert, index }: { alert: WazuhAlert; index: number }) {
  const col = sevColor(alert.severity);
  const bg  = sevBg(alert.severity);
  const techniques = alert.mitre?.technique ?? [];

  return (
    <motion.div
      key={alert.id ?? index}
      initial={{ opacity: 0, x: -16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.025 }}
      className="rounded-xl overflow-hidden border-l-4"
      style={{ borderLeftColor: col, background: bg, border: `1px solid ${col}25`, borderLeft: `4px solid ${col}` }}
    >
      <div className="p-4">
        {/* Top row: severity badge + rule_id + time */}
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className="text-[11px] font-bold px-2 py-0.5 rounded"
              style={{ color: col, background: `${col}20`, border: `1px solid ${col}40` }}
            >
              {sevLabel(alert.severity)} / {alert.severity}
            </span>
            {alert.rule_id && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-white/40 border border-white/10">
                Rule #{alert.rule_id}
              </span>
            )}
            {(alert.groups ?? []).slice(0, 2).map(g => (
              <span key={g} className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-white/40 font-mono border border-white/10">
                {g}
              </span>
            ))}
          </div>
          <div className="flex items-center gap-1 text-xs text-white/30 shrink-0">
            <Clock className="h-3 w-3" />
            {new Date(alert.timestamp).toLocaleTimeString()}
          </div>
        </div>

        {/* Rule description */}
        <p className="text-sm font-semibold text-white/90 leading-snug mb-2">
          {alert.rule || "Unknown Rule"}
        </p>

        {/* Agent + Location */}
        <div className="flex flex-wrap gap-4 text-xs text-white/50 mb-2">
          {alert.agent && (
            <span>Agent: <strong className="text-white/70">{alert.agent}</strong></span>
          )}
          {alert.location && (
            <span className="truncate max-w-xs">
              Location: <code className="text-white/50 text-[10px]">{alert.location}</code>
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
                className="text-[10px] px-2 py-0.5 rounded border font-mono flex items-center gap-1 hover:opacity-80 transition-opacity"
                style={{ color: "#FF6D00", borderColor: "#FF6D0040", background: "rgba(255,109,0,0.08)" }}
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
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-[#00D9FF] via-[#9D4EDD] to-[#FF1744] bg-clip-text text-transparent">
          Threat Intelligence
        </h1>
        <p className="text-muted-foreground">Real-time host-based security alerts from Wazuh SIEM</p>
      </motion.div>

      {/* Status bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 text-sm">
          {loading
            ? <RefreshCw className="h-3 w-3 text-yellow-400 animate-spin" />
            : error
              ? <WifiOff className="h-3 w-3 text-red-400" />
              : <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse inline-block" />}
          <span className={error ? "text-red-400 font-medium" : "text-green-400 font-medium"}>
            {loading ? "Fetching…" : error ? "Wazuh Unreachable" : "Live Wazuh Feed"}
          </span>
          {secondsAgo !== null && !loading && !error && (
            <span className="text-muted-foreground">• Updated {secondsAgo}s ago</span>
          )}
        </div>
        <button
          onClick={fetchAlerts}
          disabled={loading}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm bg-white/5 border border-white/10 hover:bg-white/10 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Error banner */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
            className="flex items-start gap-3 p-4 rounded-xl border border-red-500/30 bg-red-900/10"
          >
            <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-red-300">Could not reach Wazuh Indexer</p>
              <p className="text-xs text-red-400/70 mt-0.5">
                {error} — Ensure <code className="font-mono text-red-300/80">WAZUH_INDEXER_PASSWORD</code> is set and the Wazuh stack is running on the Kali VM.
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Severity breakdown cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {buckets.map((b, i) => (
          <motion.div
            key={b.label}
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.05 }}
          >
            <Card
              className="p-4 bg-black/40 backdrop-blur-xl relative overflow-hidden group cursor-default"
              style={{ borderColor: `${b.color}30` }}
            >
              <div
                className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                style={{ background: `linear-gradient(135deg, ${b.color}15, transparent)` }}
              />
              <p className="text-xs font-bold tracking-widest mb-1.5" style={{ color: b.color }}>
                {b.label}
              </p>
              <p className="text-3xl font-bold text-white">{b.count}</p>
              <p className="text-xs text-white/30 mt-0.5">alerts</p>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Alert feed */}
      <Card className="p-6 bg-black/40 backdrop-blur-xl border border-[#9D4EDD]/25">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-red-500" />
            Live Security Alerts
            {alerts.length > 0 && (
              <Badge variant="outline" className="ml-1 text-xs font-mono">{alerts.length}</Badge>
            )}
          </h2>
        </div>

        {alerts.length === 0 && !loading ? (
          <div className="flex flex-col items-center gap-3 py-14 text-center">
            {error ? (
              <>
                <WifiOff className="h-10 w-10 text-red-400/30" />
                <p className="text-sm text-muted-foreground max-w-sm">
                  Wazuh indexer is unreachable. Start the Wazuh stack to see live alerts.
                </p>
              </>
            ) : (
              <>
                <ShieldAlert className="h-10 w-10 text-green-500/30" />
                <p className="text-sm text-muted-foreground">No active Wazuh alerts — system appears calm.</p>
              </>
            )}
          </div>
        ) : (
          <div className="space-y-2.5 max-h-[560px] overflow-y-auto pr-1">
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
