import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Activity, ShieldAlert, Bug, BarChart2 } from "lucide-react";

type RiskScore = { score: number; label: string; color: string };
type IncidentStats = { open: number; total_incidents: number };
type MalwareStatus = { infected_count?: number; yara_hits?: number; vt_positives?: number; risk_score?: number; verdict?: string; clamav?: { infected_count: number } };

export function StatsCards() {
  const [risk,     setRisk]     = useState<RiskScore | null>(null);
  const [stats,    setStats]    = useState<IncidentStats | null>(null);
  const [malware,  setMalware]  = useState<MalwareStatus | null>(null);
  const [events,   setEvents]   = useState<number>(0);

  useEffect(() => {
    const go = async () => {
      try {
        const [rRes, sRes, mRes, eRes] = await Promise.all([
          fetch("/api/risk/score",              { cache: "no-store" }),
          fetch("/api/memory/stats",            { cache: "no-store" }),
          fetch("/api/malware/status",          { cache: "no-store" }),
          fetch("/api/threat-sentinel/events?limit=100", { cache: "no-store" }),
        ]);
        if (rRes.ok) setRisk(await rRes.json());
        if (sRes.ok) setStats(await sRes.json());
        if (mRes.ok) setMalware(await mRes.json());
        if (eRes.ok) { const d = await eRes.json(); setEvents(Array.isArray(d) ? d.length : 0); }
      } catch (_) {}
    };
    go();
  }, []);

  const cards = [
    {
      icon: BarChart2,
      label: "Risk Score",
      value: risk ? `${risk.score}/100` : "—",
      sub: risk?.label ?? "Loading…",
      accent: "#22D3EE",
    },
    {
      icon: ShieldAlert,
      label: "Open Incidents",
      value: stats ? String(stats.open) : "—",
      sub: `${stats?.total_incidents ?? 0} total tracked`,
      accent: "#F87171",
    },
    {
      icon: Activity,
      label: "Threat Events",
      value: String(events),
      sub: "From all scanners",
      accent: "#38BDF8",
    },
    {
      icon: Bug,
      label: "Malware Verdict",
      value: malware?.verdict ?? "—",
      sub: `${malware?.clamav?.infected_count ?? 0} ClamAV · ${malware?.yara_hits ?? 0} YARA`,
      accent: malware?.verdict === "CONFIRMED INFECTION" ? "#F87171" : malware?.verdict === "LIKELY COMPROMISE" ? "#FBBF24" : "#34D399",
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, i) => (
        <motion.div
          key={card.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.08 }}
          whileHover={{ y: -3, transition: { duration: 0.2 } }}
        >
          <Card
            className="glass-effect overflow-hidden relative group cursor-default"
            style={{ borderColor: `${card.accent}25` }}
          >
            {/* Shimmer */}
            <motion.div
              className="absolute inset-0 pointer-events-none"
              style={{ background: `linear-gradient(90deg, transparent, ${card.accent}08, transparent)` }}
              animate={{ x: ["-100%", "200%"] }}
              transition={{ duration: 2.5, repeat: Infinity, repeatDelay: 3 }}
            />
            {/* Hover radial */}
            <div
              className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none"
              style={{ background: `radial-gradient(circle at 30% 50%, ${card.accent}12 0%, transparent 65%)` }}
            />

            <div className="p-5 relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="p-2 rounded-lg" style={{ background: `${card.accent}15` }}>
                  <card.icon className="h-5 w-5" style={{ color: card.accent }} />
                </div>
                <div className="h-1.5 w-1.5 rounded-full animate-pulse-glow" style={{ background: card.accent }} />
              </div>
              <p className="text-xs text-muted-foreground font-medium mb-1">{card.label}</p>
              <p className="text-2xl font-bold tracking-tight" style={{ color: card.accent }}>{card.value}</p>
              <p className="text-xs text-muted-foreground mt-1 truncate">{card.sub}</p>
            </div>

            {/* Bottom accent line */}
            <div className="absolute bottom-0 left-0 right-0 h-[2px]" style={{ background: `linear-gradient(90deg, transparent, ${card.accent}60, transparent)` }} />
          </Card>
        </motion.div>
      ))}
    </div>
  );
}
