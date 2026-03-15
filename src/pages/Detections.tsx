import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Search, Filter, RotateCw, ShieldAlert, AlertTriangle, Activity, Clock } from "lucide-react";

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
  critical: "#FF1744",
  high:     "#FF6D00",
  medium:   "#FFC107",
  low:      "#00E676",
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
    const iv = setInterval(fetchEvents, 60_000); // auto-refresh every 60s
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
    <div className="space-y-6">
      {/* __ Header __ */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-[#9D4EDD] to-[#FF1744] bg-clip-text text-transparent">
          Threat Detections
        </h1>
        <p className="text-muted-foreground">Live correlated events from ClamAV · YARA · Trivy · Wazuh</p>
      </motion.div>

      {/* __ Severity summary chips __ */}
      <div className="flex flex-wrap gap-3">
        {(["all", "critical", "high", "medium", "low"] as const).map(s => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-3 py-1 rounded-full text-xs font-bold border transition-all ${
              filter === s ? "ring-2 ring-white" : "opacity-60 hover:opacity-90"
            }`}
            style={{
              borderColor: s === "all" ? "#888" : SEV_COLORS[s],
              color:       s === "all" ? "#ccc"  : SEV_COLORS[s],
            }}
          >
            {s.toUpperCase()}{s !== "all" ? ` (${counts[s] ?? 0})` : ` (${events.length})`}
          </button>
        ))}
      </div>

      {/* __ Search + refresh __ */}
      <Card className="border-border p-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by title, scanner, or type…"
              className="pl-9 bg-secondary border-border"
              value={query}
              onChange={e => setQuery(e.target.value)}
            />
          </div>
          <Button variant="outline" onClick={fetchEvents} disabled={loading} className="gap-2">
            <RotateCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Loading…" : "Refresh"}
          </Button>
        </div>
        {error && <p className="text-red-400 text-sm mt-2">{error}</p>}
      </Card>

      {/* __ Events list __ */}
      <Card className="border-border p-6">
        <h2 className="text-lg font-semibold mb-4">
          {filtered.length} Detection{filtered.length !== 1 ? "s" : ""}
          {filter !== "all" && ` — ${filter.toUpperCase()}`}
        </h2>

        {filtered.length === 0 && !loading ? (
          <p className="text-muted-foreground text-center py-8">
            {events.length === 0
              ? "No threat events yet. Backend may still be running its first scan."
              : "No events match the current filter."}
          </p>
        ) : (
          <div className="space-y-3">
            <AnimatePresence>
              {filtered.map((evt, i) => {
                const Icon = SEV_ICON[evt.severity] ?? Activity;
                return (
                  <motion.div
                    key={`${evt.id}-${i}`}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ delay: i * 0.03 }}
                    className="p-4 rounded-lg border bg-card/50 hover:bg-card transition-colors"
                    style={{ borderColor: (SEV_COLORS[evt.severity] ?? "#888") + "40" }}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3 flex-1 min-w-0">
                        <Icon className="h-5 w-5 mt-0.5 shrink-0" style={{ color: SEV_COLORS[evt.severity] }} />
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2 mb-1">
                            <Badge style={{ backgroundColor: SEV_COLORS[evt.severity] }} className="text-xs font-bold">
                              {evt.severity.toUpperCase()}
                            </Badge>
                            <Badge variant="outline" className="text-xs">{evt.scanner}</Badge>
                            {evt.id && <span className="font-mono text-xs text-muted-foreground">#{evt.id}</span>}
                          </div>
                          <h3 className="font-semibold text-sm truncate">{evt.title}</h3>
                          {evt.details?.cve && (
                            <p className="text-xs text-muted-foreground">CVE: {evt.details.cve}</p>
                          )}
                          {evt.details?.path && (
                            <p className="text-xs text-muted-foreground font-mono truncate">Path: {evt.details.path}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0 text-right">
                        <div>
                          <p className="text-xs text-muted-foreground whitespace-nowrap">
                            <Clock className="inline h-3 w-3 mr-1" />
                            {new Date(evt.timestamp).toLocaleString()}
                          </p>
                          <Badge variant={evt.status === "open" ? "destructive" : "secondary"} className="text-xs mt-1">
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
