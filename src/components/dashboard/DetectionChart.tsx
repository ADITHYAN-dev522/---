import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Card } from "@/components/ui/card";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend,
} from "recharts";

type ThreatEvent = { timestamp: string; severity: string };

function buildTimeline(events: ThreatEvent[]) {
  // Group events into 6 hourly buckets (last 24h)
  const now = Date.now();
  const buckets: { time: string; threats: number; critical: number }[] = [];
  for (let h = 20; h >= 0; h -= 4) {
    const label = new Date(now - h * 3_600_000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const from  = now - (h + 4) * 3_600_000;
    const to    = now - h * 3_600_000;
    const bucket = events.filter(e => {
      const t = new Date(e.timestamp).getTime();
      return t >= from && t < to;
    });
    buckets.push({
      time: label,
      threats:  bucket.length,
      critical: bucket.filter(e => e.severity === "critical" || e.severity === "high").length,
    });
  }
  return buckets;
}

export function DetectionChart() {
  const [data, setData] = useState<ReturnType<typeof buildTimeline>>([]);

  useEffect(() => {
    fetch("/api/threat-sentinel/events?limit=200", { cache: "no-store" })
      .then(r => r.ok ? r.json() : [])
      .then((events: ThreatEvent[]) => setData(buildTimeline(Array.isArray(events) ? events : [])))
      .catch(() => setData(buildTimeline([])));
  }, []);

  return (
    <Card className="glass-effect border-primary/20 relative overflow-hidden">
      {/* Corner accent */}
      <motion.div
        className="absolute top-0 right-0 w-28 h-28 rounded-bl-full pointer-events-none"
        style={{ background: "radial-gradient(circle, hsl(185 85% 52% / 0.12), transparent 70%)" }}
        animate={{ scale: [1, 1.08, 1], opacity: [0.5, 0.8, 0.5] }}
        transition={{ duration: 4, repeat: Infinity }}
      />

      <div className="p-6 relative z-10">
        <div className="mb-5">
          <h3 className="text-lg font-semibold">Detection Timeline</h3>
          <p className="text-sm text-muted-foreground">Threat event distribution over the last 24 hours</p>
        </div>

        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
        >
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#22D3EE" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#22D3EE" stopOpacity={0}   />
                </linearGradient>
                <linearGradient id="gCritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#F87171" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#F87171" stopOpacity={0}   />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(220 14% 16%)" opacity={0.5} />
              <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 11 }} />
              <YAxis stroke="#475569" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{
                  background: "hsl(220 16% 9%)",
                  border: "1px solid hsl(220 14% 16%)",
                  borderRadius: "8px",
                  color: "#e2e8f0",
                  fontSize: 12,
                }}
              />
              <Legend wrapperStyle={{ fontSize: 12, color: "#64748b" }} />
              <Area
                type="monotone" dataKey="threats" name="All Events"
                stroke="#22D3EE" strokeWidth={2} fill="url(#gThreats)"
                animationDuration={1200}
              />
              <Area
                type="monotone" dataKey="critical" name="Critical/High"
                stroke="#F87171" strokeWidth={2} fill="url(#gCritical)"
                animationDuration={1400}
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-gradient-primary opacity-30" />
    </Card>
  );
}
