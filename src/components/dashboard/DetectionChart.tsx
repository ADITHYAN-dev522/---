import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Card } from "@/components/ui/card";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend,
} from "recharts";

type ThreatEvent = { timestamp: string; severity: string };

function buildTimeline(events: ThreatEvent[]) {
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
    <Card className="glass-elevated relative overflow-hidden">
      {/* Corner glow */}
      <motion.div
        className="absolute -top-10 -right-10 w-40 h-40 rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle, hsl(185 85% 50% / 0.08), transparent 70%)" }}
        animate={{ scale: [1, 1.1, 1], opacity: [0.4, 0.7, 0.4] }}
        transition={{ duration: 5, repeat: Infinity }}
      />

      <div className="p-5 relative z-10">
        <div className="mb-4">
          <h3 className="text-sm font-semibold">Detection Timeline</h3>
          <p className="text-[11px] text-muted-foreground/50">Threat event distribution — last 24 hours</p>
        </div>

        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
        >
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0}   />
                </linearGradient>
                <linearGradient id="gCritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0}   />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(225 16% 13%)" opacity={0.4} />
              <XAxis dataKey="time" stroke="#334155" tick={{ fontSize: 10, fill: "#475569" }} />
              <YAxis stroke="#334155" tick={{ fontSize: 10, fill: "#475569" }} />
              <Tooltip
                contentStyle={{
                  background: "hsl(228 20% 6% / 0.95)",
                  border: "1px solid hsl(225 16% 15%)",
                  borderRadius: "10px",
                  color: "#e2e8f0",
                  fontSize: 11,
                  backdropFilter: "blur(12px)",
                  boxShadow: "0 8px 32px hsl(228 20% 5% / 0.5)",
                }}
              />
              <Legend wrapperStyle={{ fontSize: 11, color: "#475569" }} />
              <Area
                type="monotone" dataKey="threats" name="All Events"
                stroke="#00d4ff" strokeWidth={2} fill="url(#gThreats)"
                animationDuration={1400}
              />
              <Area
                type="monotone" dataKey="critical" name="Critical/High"
                stroke="#ef4444" strokeWidth={2} fill="url(#gCritical)"
                animationDuration={1600}
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      <div
        className="absolute bottom-0 left-0 right-0 h-[1px]"
        style={{ background: "linear-gradient(90deg, transparent, #00d4ff30, transparent)" }}
      />
    </Card>
  );
}
