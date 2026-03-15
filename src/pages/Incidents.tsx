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
  critical: "#FF1744",
  high:     "#FF6D00",
  medium:   "#FFC107",
  low:      "#00E676",
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
    <div className="space-y-6">
      {/* ── Header ── */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-[#FF6D00] to-[#FF1744] bg-clip-text text-transparent">
          Incident Management
        </h1>
        <p className="text-muted-foreground">Track and resolve security incidents from the SQLite memory store</p>
      </motion.div>

      {/* ── Refresh + error ── */}
      <div className="flex items-center gap-3">
        <Button variant="outline" onClick={fetchAll} disabled={loading} className="gap-2">
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Loading…" : "Refresh"}
        </Button>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {/* ── Stats cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Open",     value: stats?.open ?? openIncidents.length,     color: "#FF1744", icon: XCircle },
          { label: "Resolved", value: stats?.resolved ?? resolvedIncidents.length, color: "#00E676", icon: CheckCircle },
          { label: "Total",    value: stats?.total_incidents ?? incidents.length, color: "#00D9FF", icon: FileText },
          { label: "Recurring Patterns", value: stats?.recurring_patterns ?? 0, color: "#FFC107", icon: AlertTriangle },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.08 }}>
            <Card className="p-5 bg-black/40 backdrop-blur-xl border" style={{ borderColor: s.color + "30" }}>
              <s.icon className="h-6 w-6 mb-2" style={{ color: s.color }} />
              <h3 className="text-2xl font-bold text-white">{s.value}</h3>
              <p className="text-sm text-muted-foreground">{s.label} Incidents</p>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* ── Top recurring patterns ── */}
      {stats?.top_patterns && stats.top_patterns.length > 0 && (
        <Card className="p-5 bg-black/40 backdrop-blur-xl border border-yellow-500/20">
          <h2 className="font-semibold mb-3 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-yellow-400" /> Recurring Attack Patterns
          </h2>
          <div className="space-y-2">
            {stats.top_patterns.map((p, i) => (
              <div key={i} className="flex justify-between items-center text-sm">
                <span className="font-mono text-muted-foreground truncate">{p.signature}</span>
                <div className="flex gap-2 items-center">
                  <Badge style={{ backgroundColor: SEV_COLORS[p.severity] ?? "#888" }} className="text-xs">{p.severity}</Badge>
                  <span className="text-muted-foreground">{p.hit_count}×</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* __ Open incidents __ */}
      <Card className="border-border p-6">
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <XCircle className="h-5 w-5 text-red-400" /> Open Incidents ({openIncidents.length})
        </h2>
        {openIncidents.length === 0 ? (
          <p className="text-muted-foreground text-center py-6">
            {incidents.length === 0 ? "No incident data yet — backend may still be scanning." : "All incidents resolved! ✅"}
          </p>
        ) : (
          <div className="space-y-3">
            <AnimatePresence>
              {openIncidents.map((inc, i) => (
                <motion.div key={inc.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, height: 0 }} transition={{ delay: i * 0.04 }}
                  className="p-4 rounded-lg border bg-card/50" style={{ borderColor: (SEV_COLORS[inc.severity] ?? "#888") + "40" }}>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <Badge style={{ backgroundColor: SEV_COLORS[inc.severity] }} className="text-xs">{inc.severity.toUpperCase()}</Badge>
                        <Badge variant="outline" className="text-xs">{inc.scanner}</Badge>
                        <span className="font-mono text-xs text-muted-foreground">#{inc.id}</span>
                      </div>
                      <h3 className="font-semibold text-sm">{inc.title}</h3>
                      <div className="flex items-center gap-1 mt-1 text-xs text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        {new Date(inc.timestamp).toLocaleString()}
                      </div>
                    </div>
                    <Button size="sm" variant="outline" disabled={resolving === inc.id}
                      onClick={() => handleResolve(inc.id)}
                      className="gap-1 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10">
                      <CheckCircle className="h-3 w-3" />
                      {resolving === inc.id ? "Resolving…" : "Resolve"}
                    </Button>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </Card>

      {/* __ Resolved incidents __ */}
      {resolvedIncidents.length > 0 && (
        <Card className="border-border p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <CheckCircle className="h-5 w-5 text-emerald-400" /> Resolved ({resolvedIncidents.length})
          </h2>
          <div className="space-y-2">
            {resolvedIncidents.slice(0, 10).map((inc, i) => (
              <motion.div key={inc.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }}
                className="p-3 rounded-lg border border-emerald-500/10 bg-card/20 flex justify-between items-center">
                <div>
                  <span className="text-sm text-muted-foreground">{inc.title}</span>
                  <span className="ml-2 font-mono text-xs text-muted-foreground">#{inc.id}</span>
                </div>
                <Badge variant="secondary" className="text-xs">resolved</Badge>
              </motion.div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
