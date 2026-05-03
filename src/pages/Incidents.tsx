import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { FileText, Clock, CheckCircle, RefreshCw, AlertTriangle, XCircle } from "lucide-react";

/* ========================= TYPES ========================= */
type Incident = {
  id: string;
  timestamp: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  scanner: string;
  title: string;
  details: Record<string, any>;
  status: "open" | "resolved";
  resolved_at?: string;
};

type Stats = {
  total_incidents: number;
  open: number;
  in_progress: number;
  resolved: number;
  recurring_patterns: number;
  top_patterns: Array<{ signature: string; hit_count: number; severity: string }>;
};

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#10b981",
};

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [stats, setStats]         = useState<Stats | null>(null);
  const [loading, setLoading]     = useState(false);
  const [resolving, setResolving] = useState<string | null>(null);
  const [error, setError]         = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [incRes, statRes] = await Promise.all([
        fetch("/api/memory/incidents?limit=50", { cache: "no-store" }),
        fetch("/api/memory/stats", { cache: "no-store" }),
      ]);
      if (!incRes.ok || !statRes.ok) throw new Error("Failed to fetch incident data");
      const [incData, statData] = await Promise.all([incRes.json(), statRes.json()]);
      setIncidents(Array.isArray(incData) ? incData : []);
      setStats(statData);
    } catch (e: any) {
      setError(e.message || "Failed to fetch");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const handleResolve = async (id: string) => {
    setResolving(id);
    try {
      const res = await fetch(`/api/memory/incidents/${id}/resolve`, { method: "PATCH" });
      if (!res.ok) throw new Error("Failed to resolve");
      await fetchAll();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setResolving(null);
    }
  };

  const openIncidents = incidents.filter(i => i.status === "open");
  const resolvedIncidents = incidents.filter(i => i.status === "resolved");

  return (
    <div className="space-y-5">
      {/* ── Header ── */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-1">
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{
            background: "linear-gradient(135deg, #f97316, #ef4444)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}
        >
          Incident Management
        </h1>
        <p className="text-sm text-muted-foreground/60">Track and resolve security incidents from the SQLite memory store</p>
      </motion.div>

      {/* ── Refresh + error ── */}
      <div className="flex items-center gap-3">
        <Button variant="outline" onClick={fetchAll} disabled={loading} className="gap-2 h-8 text-xs rounded-lg border-border/40 hover:bg-white/5">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Loading…" : "Refresh"}
        </Button>
        {error && <p className="text-red-400/80 text-xs">{error}</p>}
      </div>

      {/* ── Stats cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: "Open",     value: stats?.open ?? openIncidents.length,     color: "#ef4444", icon: XCircle },
          { label: "Resolved", value: stats?.resolved ?? resolvedIncidents.length, color: "#10b981", icon: CheckCircle },
          { label: "Total",    value: stats?.total_incidents ?? incidents.length, color: "#00d4ff", icon: FileText },
          { label: "Recurring", value: stats?.recurring_patterns ?? 0, color: "#eab308", icon: AlertTriangle },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.06 }} whileHover={{ y: -2 }}>
            <Card className="glass-elevated p-4 relative overflow-hidden group cursor-default" style={{ borderColor: `${s.color}18` }}>
              <div
                className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
                style={{ background: `radial-gradient(circle at 30% 50%, ${s.color}08, transparent 65%)` }}
              />
              <s.icon className="h-5 w-5 mb-2 relative z-10" style={{ color: s.color }} />
              <h3 className="text-xl font-bold relative z-10" style={{ color: s.color }}>{s.value}</h3>
              <p className="text-[10px] text-muted-foreground/50 relative z-10">{s.label} Incidents</p>
              <div className="absolute bottom-0 left-0 right-0 h-[1px]" style={{ background: `linear-gradient(90deg, transparent, ${s.color}30, transparent)` }} />
            </Card>
          </motion.div>
        ))}
      </div>

      {/* ── Top recurring patterns ── */}
      {stats?.top_patterns && stats.top_patterns.length > 0 && (
        <Card className="glass-elevated p-5" style={{ borderColor: "#eab30818" }}>
          <h2 className="font-semibold text-sm mb-3 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-yellow-400/80" /> Recurring Attack Patterns
          </h2>
          <div className="space-y-2">
            {stats.top_patterns.map((p, i) => (
              <div key={i} className="flex justify-between items-center text-sm">
                <span className="font-mono text-[11px] text-muted-foreground/60 truncate">{p.signature}</span>
                <div className="flex gap-2 items-center">
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ color: SEV_COLORS[p.severity] ?? "#64748b", background: `${SEV_COLORS[p.severity] ?? "#64748b"}15` }}>
                    {p.severity}
                  </span>
                  <span className="text-[10px] text-muted-foreground/50 font-mono tabular-nums">{p.hit_count}×</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* __ Open incidents __ */}
      <Card className="glass-elevated p-5">
        <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <XCircle className="h-4 w-4 text-red-400/80" /> Open Incidents ({openIncidents.length})
        </h2>
        {openIncidents.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-10">
            <CheckCircle className="h-8 w-8 text-emerald-400/20" />
            <p className="text-muted-foreground/50 text-sm">
              {incidents.length === 0 ? "No incident data yet — backend may still be scanning." : "All incidents resolved! ✅"}
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            <AnimatePresence>
              {openIncidents.map((inc, i) => {
                const col = SEV_COLORS[inc.severity] ?? "#64748b";
                return (
                  <motion.div key={inc.id} initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, height: 0 }} transition={{ delay: i * 0.03 }}
                    className="p-3.5 rounded-xl border hover:bg-white/[0.02] transition-colors" style={{ borderColor: `${col}20`, background: `${col}05` }}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5 mb-1">
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ color: col, background: `${col}15`, border: `1px solid ${col}25` }}>
                            {inc.severity.toUpperCase()}
                          </span>
                          <Badge variant="outline" className="text-[10px] h-4 border-border/30">{inc.scanner}</Badge>
                          <span className="font-mono text-[10px] text-muted-foreground/40">#{inc.id}</span>
                        </div>
                        <h3 className="font-medium text-[13px]">{inc.title}</h3>
                        <div className="flex items-center gap-1 mt-1 text-[10px] text-muted-foreground/40">
                          <Clock className="h-2.5 w-2.5" />
                          {new Date(inc.timestamp).toLocaleString()}
                        </div>
                      </div>
                      <Button size="sm" variant="outline" disabled={resolving === inc.id}
                        onClick={() => handleResolve(inc.id)}
                        className="gap-1 h-7 text-[10px] border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10 rounded-lg">
                        <CheckCircle className="h-3 w-3" />
                        {resolving === inc.id ? "Resolving…" : "Resolve"}
                      </Button>
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        )}
      </Card>

      {/* __ Resolved incidents __ */}
      {resolvedIncidents.length > 0 && (
        <Card className="glass-elevated p-5">
          <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-emerald-400/80" /> Resolved ({resolvedIncidents.length})
          </h2>
          <div className="space-y-1.5">
            {resolvedIncidents.slice(0, 10).map((inc, i) => (
              <motion.div key={inc.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }}
                className="p-2.5 rounded-lg border border-emerald-500/8 bg-emerald-500/[0.02] flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-3 w-3 text-emerald-400/40" />
                  <span className="text-[12px] text-muted-foreground/60">{inc.title}</span>
                  <span className="ml-1 font-mono text-[10px] text-muted-foreground/30">#{inc.id}</span>
                </div>
                <Badge variant="secondary" className="text-[9px] h-4">resolved</Badge>
              </motion.div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
