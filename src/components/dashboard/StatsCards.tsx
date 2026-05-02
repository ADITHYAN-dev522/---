import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, ShieldAlert, Bug, BarChart2 } from "lucide-react";

type RiskScore = { score: number; label: string; color: string };
type IncidentStats = { open: number; total_incidents: number };
type MalwareStatus = { clamav?: { infected_count: number }; yara_hits?: number; risk_score?: number; verdict?: string };

function useCount(target: number, duration = 1000) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (target === 0) { setVal(0); return; }
    let start = 0;
    const step = target / (duration / 16);
    const t = setInterval(() => {
      start = Math.min(start + step, target);
      setVal(Math.round(start));
      if (start >= target) clearInterval(t);
    }, 16);
    return () => clearInterval(t);
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
    <Card className="glass-effect overflow-hidden relative group cursor-default" style={{ borderColor: `${accent}25` }}>
      <motion.div
        className="absolute inset-0 pointer-events-none"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}06, transparent)` }}
        animate={{ x: ["-100%", "200%"] }}
        transition={{ duration: 3, repeat: Infinity, repeatDelay: 4 }}
      />
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none"
        style={{ background: `radial-gradient(circle at 30% 50%, ${accent}10 0%, transparent 65%)` }} />
      <div className="p-5 relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className="p-2 rounded-lg" style={{ background: `${accent}15` }}>
            <Icon className="h-5 w-5" style={{ color: accent }} />
          </div>
          <div className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: accent }} />
        </div>
        <p className="text-xs text-muted-foreground font-medium mb-1">{label}</p>
        <p className="text-2xl font-bold tracking-tight" style={{ color: accent }}>{display}</p>
        <p className="text-xs text-muted-foreground mt-1 truncate">{sub}</p>
      </div>
      <div className="absolute bottom-0 left-0 right-0 h-[2px]"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}50, transparent)` }} />
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
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        icon={BarChart2} label="Risk Score"
        rawValue={risk ? `${risk.score}/100` : "—"}
        numericValue={risk?.score}
        sub={risk?.label ?? "Calculating…"}
        accent="#22D3EE"
      />
      <StatCard
        icon={ShieldAlert} label="Open Incidents"
        rawValue={stats ? String(stats.open) : "—"}
        numericValue={stats?.open}
        sub={`${stats?.total_incidents ?? 0} total tracked`}
        accent="#F87171"
      />
      <StatCard
        icon={Activity} label="Threat Events"
        rawValue={String(events)}
        numericValue={events}
        sub="From all scanners"
        accent="#38BDF8"
      />
      <StatCard
        icon={Bug} label="Malware Verdict"
        rawValue={malware?.verdict ?? "—"}
        sub={`${malware?.clamav?.infected_count ?? 0} ClamAV · ${malware?.yara_hits ?? 0} YARA hits`}
        accent={malware?.verdict === "CONFIRMED INFECTION" ? "#F87171" : malware?.verdict === "LIKELY COMPROMISE" ? "#FBBF24" : "#34D399"}
      />
    </div>
  );
}
