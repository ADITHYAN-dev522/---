import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Activity, ShieldAlert, Bug, BarChart2 } from "lucide-react";

type RiskScore = { score: number; label: string; color: string };
type IncidentStats = { open: number; total_incidents: number };
type MalwareStatus = { clamav?: { infected_count: number }; yara_hits?: number; risk_score?: number; verdict?: string };

function useCount(target: number, duration = 1200) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (target === 0) { setVal(0); return; }
    const start = performance.now();
    let frame: number;
    const animate = (now: number) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setVal(Math.round(eased * target));
      if (progress < 1) frame = requestAnimationFrame(animate);
    };
    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [target, duration]);
  return val;
}

function StatCard({ icon: Icon, label, rawValue, numericValue, sub, accent }: {
  icon: React.ElementType; label: string; rawValue: string;
  numericValue?: number; sub: string; accent: string;
}) {
  const counted = useCount(numericValue ?? 0);
  const display = numericValue !== undefined ? (rawValue.includes("/") ? `${counted}/100` : String(counted)) : rawValue;

  return (
    <Card className="glass-elevated overflow-hidden relative group cursor-default" style={{ borderColor: `${accent}18` }}>
      {/* Shimmer sweep */}
      <motion.div
        className="absolute inset-0 pointer-events-none"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}05, transparent)` }}
        animate={{ x: ["-100%", "200%"] }}
        transition={{ duration: 4, repeat: Infinity, repeatDelay: 5 }}
      />
      {/* Hover radial glow */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
        style={{ background: `radial-gradient(circle at 30% 50%, ${accent}0A 0%, transparent 65%)` }}
      />
      <div className="p-5 relative z-10">
        <div className="flex items-center justify-between mb-3">
          <div className="p-2 rounded-lg" style={{ background: `${accent}10` }}>
            <Icon className="h-4 w-4" style={{ color: accent }} />
          </div>
          <div
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: accent, boxShadow: `0 0 6px ${accent}80` }}
          />
        </div>
        <p className="text-[10px] text-muted-foreground/60 font-medium mb-1 uppercase tracking-wider">{label}</p>
        <p className="text-2xl font-bold tracking-tight tabular-nums" style={{ color: accent }}>{display}</p>
        <p className="text-[10px] text-muted-foreground/40 mt-1 truncate">{sub}</p>
      </div>
      <div
        className="absolute bottom-0 left-0 right-0 h-[1px]"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}40, transparent)` }}
      />
    </Card>
  );
}

export function StatsCards() {
  const [risk,    setRisk]    = useState<RiskScore | null>(null);
  const [stats,   setStats]   = useState<IncidentStats | null>(null);
  const [malware, setMalware] = useState<MalwareStatus | null>(null);
  const [events,  setEvents]  = useState(0);

  useEffect(() => {
    const go = async () => {
      try {
        const [rRes, sRes, mRes, eRes] = await Promise.all([
          fetch("/api/risk/score",              { cache: "no-store" }),
          fetch("/api/memory/stats",            { cache: "no-store" }),
          fetch("/api/malware/status",          { cache: "no-store" }),
          fetch("/api/threat-sentinel/events?limit=200", { cache: "no-store" }),
        ]);
        if (rRes.ok) setRisk(await rRes.json());
        if (sRes.ok) setStats(await sRes.json());
        if (mRes.ok) setMalware(await mRes.json());
        if (eRes.ok) { const d = await eRes.json(); setEvents(Array.isArray(d) ? d.length : 0); }
      } catch (_) {}
    };
    go();
  }, []);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
      {[
        {
          icon: BarChart2, label: "Risk Score",
          rawValue: risk ? `${risk.score}/100` : "—",
          numericValue: risk?.score,
          sub: risk?.label ?? "Calculating…",
          accent: "#00d4ff",
        },
        {
          icon: ShieldAlert, label: "Open Incidents",
          rawValue: stats ? String(stats.open) : "—",
          numericValue: stats?.open,
          sub: `${stats?.total_incidents ?? 0} total tracked`,
          accent: "#ef4444",
        },
        {
          icon: Activity, label: "Threat Events",
          rawValue: String(events),
          numericValue: events,
          sub: "From all scanners",
          accent: "#38bdf8",
        },
        {
          icon: Bug, label: "Malware Verdict",
          rawValue: malware?.verdict ?? "—",
          sub: `${malware?.clamav?.infected_count ?? 0} ClamAV · ${malware?.yara_hits ?? 0} YARA hits`,
          accent: malware?.verdict === "CONFIRMED INFECTION" ? "#ef4444" : malware?.verdict === "LIKELY COMPROMISE" ? "#eab308" : "#10b981",
        },
      ].map((s, i) => (
        <motion.div
          key={s.label}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.08 + i * 0.06 }}
          whileHover={{ y: -2 }}
        >
          <StatCard {...s} />
        </motion.div>
      ))}
    </div>
  );
}
