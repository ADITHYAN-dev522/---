import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Search, RotateCw, ShieldAlert, AlertTriangle, Activity, Clock, Radar } from "lucide-react";
import { SkeletonFeed } from "@/components/ui/skeleton-loader";

/* ========================= TYPES ========================= */
type ThreatEvent = {
  id: string | null;
  timestamp: string;
  type: string;
  scanner: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  details: Record<string, any>;
  status: string;
};

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#10b981",
};

const SEV_ICON: Record<string, React.ElementType> = {
  critical: ShieldAlert,
  high:     AlertTriangle,
  medium:   Activity,
  low:      Activity,
};

export default function Detections() {
  const [events, setEvents]     = useState<ThreatEvent[]>([]);
  const [loading, setLoading]   = useState(false);
  const [query, setQuery]       = useState("");
  const [filter, setFilter]     = useState<string>("all");
  const [error, setError]       = useState<string | null>(null);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/threat-sentinel/events?limit=100", { cache: "no-store" });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setEvents(Array.isArray(data) ? data : []);
    } catch (e: any) {
      setError(e.message || "Failed to fetch threat events");
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEvents();
    const iv = setInterval(fetchEvents, 60_000);
    return () => clearInterval(iv);
  }, [fetchEvents]);

  /* ── Filter + search ── */
  const filtered = events.filter(e => {
    const matchesSev   = filter === "all" || e.severity === filter;
    const matchesQuery = query
      ? e.title.toLowerCase().includes(query.toLowerCase()) ||
        e.scanner.toLowerCase().includes(query.toLowerCase()) ||
        e.type.toLowerCase().includes(query.toLowerCase())
      : true;
    return matchesSev && matchesQuery;
  });

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  events.forEach(e => { if (e.severity in counts) counts[e.severity as keyof typeof counts]++; });

  return (
    <div className="space-y-5">
      {/* __ Header __ */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-1">
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{
            background: "linear-gradient(135deg, #8b5cf6, #ef4444)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}
        >
          Threat Detections
        </h1>
        <p className="text-sm text-muted-foreground/60">Live correlated events from ClamAV · YARA · Trivy · Wazuh</p>
      </motion.div>

      {/* __ Severity summary chips __ */}
      <div className="flex flex-wrap gap-2">
        {(["all", "critical", "high", "medium", "low"] as const).map(s => {
          const active = filter === s;
          const col = s === "all" ? "#64748b" : SEV_COLORS[s];
          return (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className="px-3 py-1 rounded-full text-[11px] font-bold border transition-all"
              style={{
                borderColor: active ? col : `${col}30`,
                color: active ? col : `${col}80`,
                background: active ? `${col}15` : "transparent",
                boxShadow: active ? `0 0 12px ${col}20` : "none",
              }}
            >
              {s.toUpperCase()}{s !== "all" ? ` (${counts[s] ?? 0})` : ` (${events.length})`}
            </button>
          );
        })}
      </div>

      {/* __ Search + refresh __ */}
      <Card className="glass-elevated p-3">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground/40" />
            <Input
              placeholder="Search by title, scanner, or type…"
              className="pl-9 h-9 text-xs bg-muted/30 border-transparent focus:border-primary/20 rounded-lg"
              value={query}
              onChange={e => setQuery(e.target.value)}
            />
          </div>
          <Button variant="outline" onClick={fetchEvents} disabled={loading} className="gap-2 h-9 text-xs rounded-lg border-border/40 hover:bg-white/5">
            <RotateCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Loading…" : "Refresh"}
          </Button>
        </div>
        {error && <p className="text-red-400/80 text-xs mt-2">{error}</p>}
      </Card>

      {/* __ Events list __ */}
      <Card className="glass-elevated p-5">
        <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <Radar className="h-4 w-4 text-primary/50" />
          {filtered.length} Detection{filtered.length !== 1 ? "s" : ""}
          {filter !== "all" && <span className="text-muted-foreground/50 font-normal">— {filter.toUpperCase()}</span>}
        </h2>

        {filtered.length === 0 && !loading ? (
          <div className="flex flex-col items-center gap-3 py-12">
            <ShieldAlert className="h-10 w-10 text-primary/10" />
            <p className="text-muted-foreground/50 text-sm">
              {events.length === 0
                ? "No threat events yet. Backend may still be running its first scan."
                : "No events match the current filter."}
            </p>
          </div>
        ) : loading && events.length === 0 ? (
          <SkeletonFeed rows={6} />
        ) : (
          <div className="space-y-2">
            <AnimatePresence>
              {filtered.map((evt, i) => {
                const Icon = SEV_ICON[evt.severity] ?? Activity;
                const col = SEV_COLORS[evt.severity] ?? "#64748b";
                return (
                  <motion.div
                    key={`${evt.id}-${i}`}
                    initial={{ opacity: 0, x: -16 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ delay: i * 0.02 }}
                    className="p-3.5 rounded-xl border hover:bg-white/[0.02] transition-colors group"
                    style={{ borderColor: `${col}20`, background: `${col}05` }}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-3 flex-1 min-w-0">
                        <div className="p-1.5 rounded-lg mt-0.5 shrink-0" style={{ background: `${col}12` }}>
                          <Icon className="h-3.5 w-3.5" style={{ color: col }} />
                        </div>
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-1.5 mb-1">
                            <span
                              className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                              style={{ color: col, background: `${col}15`, border: `1px solid ${col}25` }}
                            >
                              {evt.severity.toUpperCase()}
                            </span>
                            <Badge variant="outline" className="text-[10px] border-border/30 h-4">{evt.scanner}</Badge>
                            {evt.id && <span className="font-mono text-[10px] text-muted-foreground/40">#{evt.id}</span>}
                          </div>
                          <h3 className="font-medium text-[13px] truncate">{evt.title}</h3>
                          {evt.details?.cve && (
                            <p className="text-[10px] text-muted-foreground/50 mt-0.5">CVE: {evt.details.cve}</p>
                          )}
                          {evt.details?.path && (
                            <p className="text-[10px] text-muted-foreground/40 font-mono truncate mt-0.5">Path: {evt.details.path}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0 text-right">
                        <div>
                          <p className="text-[10px] text-muted-foreground/40 whitespace-nowrap flex items-center gap-0.5">
                            <Clock className="inline h-2.5 w-2.5" />
                            {new Date(evt.timestamp).toLocaleString()}
                          </p>
                          <Badge variant={evt.status === "open" ? "destructive" : "secondary"} className="text-[9px] mt-1 h-4">
                            {evt.status}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        )}
      </Card>
    </div>
  );
}
