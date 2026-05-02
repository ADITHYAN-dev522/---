import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { RotateCw, ShieldAlert, AlertTriangle, Activity } from "lucide-react";

type ThreatEvent = {
  id: string | null;
  timestamp: string;
  type: string;
  scanner: string;
  severity: string;
  title: string;
  status: string;
};

const SEV: Record<string, { color: string; bg: string }> = {
  critical: { color: "#F87171", bg: "rgba(248,113,113,0.12)" },
  high:     { color: "#FB923C", bg: "rgba(251,146,60,0.10)"  },
  medium:   { color: "#FBBF24", bg: "rgba(251,191,36,0.09)"  },
  low:      { color: "#34D399", bg: "rgba(52,211,153,0.08)"  },
};

const SEV_ICON: Record<string, React.ElementType> = {
  critical: ShieldAlert,
  high:     AlertTriangle,
  medium:   Activity,
  low:      Activity,
};

export function RecentAlerts() {
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [loading, setLoading] = useState(false);

  const fetch_ = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/threat-sentinel/events?limit=8", { cache: "no-store" });
      if (res.ok) {
        const d = await res.json();
        setEvents(Array.isArray(d) ? d.slice(0, 8) : []);
      }
    } catch (_) {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetch_(); }, [fetch_]);

  return (
    <Card className="glass-effect border-primary/20 relative overflow-hidden">
      <div className="p-6 relative z-10">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-lg font-semibold">Recent Threat Events</h3>
            <p className="text-sm text-muted-foreground">Latest correlated detections from all scanners</p>
          </div>
          <button
            onClick={fetch_}
            disabled={loading}
            className="p-1.5 rounded-lg bg-primary/10 border border-primary/20 hover:bg-primary/20 transition-colors disabled:opacity-50"
          >
            <RotateCw className={`h-4 w-4 text-primary ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>

        {events.length === 0 && !loading ? (
          <div className="flex flex-col items-center gap-2 py-10 text-center">
            <ShieldAlert className="h-10 w-10 text-primary/20" />
            <p className="text-sm text-muted-foreground">No events yet — backend may still be scanning.</p>
          </div>
        ) : (
          <div className="space-y-2">
            <AnimatePresence>
              {events.map((e, i) => {
                const s = SEV[e.severity] ?? { color: "#94A3B8", bg: "rgba(148,163,184,0.07)" };
                const Icon = SEV_ICON[e.severity] ?? Activity;
                return (
                  <motion.div
                    key={`${e.id}-${i}`}
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04 }}
                    className="flex items-center gap-3 p-3 rounded-xl border-l-4 group hover:brightness-110 transition-all"
                    style={{ borderLeftColor: s.color, background: s.bg, border: `1px solid ${s.color}20`, borderLeft: `3px solid ${s.color}` }}
                  >
                    <Icon className="h-4 w-4 shrink-0" style={{ color: s.color }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{e.title}</p>
                      <p className="text-xs text-muted-foreground">{e.scanner} · {new Date(e.timestamp).toLocaleTimeString()}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                        style={{ color: s.color, background: `${s.color}20`, border: `1px solid ${s.color}30` }}
                      >
                        {e.severity.toUpperCase()}
                      </span>
                      <Badge variant={e.status === "open" ? "destructive" : "secondary"} className="text-[10px]">
                        {e.status}
                      </Badge>
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        )}
      </div>
      {/* Bottom gradient accent */}
      <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-gradient-primary opacity-40" />
    </Card>
  );
}
