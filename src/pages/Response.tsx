import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Zap, CheckCircle, RefreshCw, Copy, Package, Terminal, AlertTriangle, Filter, ExternalLink } from "lucide-react";
import { SkeletonStats, SkeletonFeed } from "@/components/ui/skeleton-loader";

/* ========================= TYPES ========================= */
type Recommendation = {
  cve: string;
  severity: "critical" | "high" | "medium" | "low";
  package: string;
  installed_version: string;
  fixed_version: string;
  title: string;
  package_manager: string;
  fix_command: string;
  reference: string;
  can_auto_patch: boolean;
  source: string;
};

/* ========================= CONSTANTS ========================= */
const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#10b981",
};

const PKG_MGR_ICON: Record<string, string> = {
  pip: "🐍", npm: "📦", apt: "🛡️", yum: "🛡️",
  gem: "💎", cargo: "⚙️", go: "🔵", unknown: "🔧",
};

const PKG_MGR_COLOR: Record<string, string> = {
  pip: "#3b82f6", npm: "#ef4444", apt: "#8b5cf6", yum: "#8b5cf6",
  gem: "#ec4899", cargo: "#f59e0b", go: "#06b6d4", unknown: "#64748b",
};

const SEVERITY_ORDER: ("all" | "critical" | "high" | "medium" | "low")[] = [
  "all", "critical", "high", "medium", "low",
];

/* ========================= COMPONENT ========================= */
export default function Response() {
  const [recs, setRecs]             = useState<Recommendation[]>([]);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState<string | null>(null);
  const [copied, setCopied]         = useState<string | null>(null);
  const [filter, setFilter]         = useState<"all" | "critical" | "high" | "medium" | "low">("all");

  const fetchRecs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/patchmaster/recommendations?limit=100", { cache: "no-store" });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setRecs(Array.isArray(data) ? data : []);
    } catch (e: any) {
      setError(e.message || "Failed to fetch recommendations");
      setRecs([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchRecs(); }, [fetchRecs]);

  const copyCmd = (cmd: string, key: string) => {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopied(key);
      setTimeout(() => setCopied(null), 2000);
    });
  };

  const filtered = filter === "all" ? recs : recs.filter(r => r.severity === filter);

  const counts = {
    all:      recs.length,
    critical: recs.filter(r => r.severity === "critical").length,
    high:     recs.filter(r => r.severity === "high").length,
    medium:   recs.filter(r => r.severity === "medium").length,
    low:      recs.filter(r => r.severity === "low").length,
  };
  const autoCount = recs.filter(r => r.can_auto_patch).length;

  return (
    <div className="space-y-5">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-1">
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{
            background: "linear-gradient(135deg, #10b981, #00d4ff, #38bdf8)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}
        >
          PatchMaster — Automated Response
        </h1>
        <p className="text-sm text-muted-foreground/60">
          CVE-mapped remediation commands generated from live vulnerability scan results
        </p>
      </motion.div>

      {/* Stats row */}
      {loading && recs.length === 0 ? <SkeletonStats /> : (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: "Total Fixes",       value: recs.length,     color: "#00d4ff", icon: Zap },
          { label: "Auto-Patchable",    value: autoCount,       color: "#10b981", icon: CheckCircle },
          { label: "Critical Priority", value: counts.critical, color: "#ef4444", icon: AlertTriangle },
          { label: "High Priority",     value: counts.high,     color: "#f97316", icon: AlertTriangle },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }} whileHover={{ y: -2 }}>
            <Card className="glass-elevated p-4 relative overflow-hidden group cursor-default" style={{ borderColor: `${s.color}15` }}>
              <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
                style={{ background: `radial-gradient(circle at 30% 50%, ${s.color}08, transparent 65%)` }} />
              <s.icon className="h-4 w-4 mb-2 relative z-10" style={{ color: s.color }} />
              <h3 className="text-xl font-bold relative z-10" style={{ color: s.color }}>{s.value}</h3>
              <p className="text-[10px] text-muted-foreground/50 mt-0.5 relative z-10">{s.label}</p>
              <div className="absolute bottom-0 left-0 right-0 h-[1px]"
                style={{ background: `linear-gradient(90deg, transparent, ${s.color}30, transparent)` }} />
            </Card>
          </motion.div>
        ))}
      </div>
      )}

      {/* Controls row */}
      <div className="flex items-center gap-3 flex-wrap">
        <Button variant="outline" onClick={fetchRecs} disabled={loading} className="gap-2 h-8 text-xs rounded-lg border-border/40 hover:bg-white/5">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Loading…" : "Refresh"}
        </Button>
        {error && <p className="text-red-400/80 text-xs">{error}</p>}

        {/* Severity filter pills */}
        <div className="ml-auto flex items-center gap-1.5 flex-wrap">
          <Filter className="h-3 w-3 text-muted-foreground/30" />
          {SEVERITY_ORDER.map(sev => {
            const col = sev === "all" ? "#64748b" : SEV_COLORS[sev];
            const active = filter === sev;
            return (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className="px-2.5 py-1 rounded-full text-[10px] font-semibold border transition-all"
                style={{
                  borderColor: active ? col : `${col}25`,
                  background:  active ? `${col}15` : "transparent",
                  color:       active ? col : `${col}60`,
                  boxShadow:   active ? `0 0 10px ${col}15` : "none",
                }}
              >
                {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
                <span className="ml-0.5 opacity-60">
                  ({sev === "all" ? counts.all : counts[sev]})
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Remediation list */}
      <Card className="glass-elevated p-5">
        <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary/60" />
          Remediation Playbook
          <span className="text-[10px] text-muted-foreground/40 font-normal ml-1">
            {filtered.length} of {recs.length} shown
          </span>
        </h2>

        {loading && recs.length === 0 ? <SkeletonFeed rows={5} /> : filtered.length === 0 && !loading ? (
          <div className="flex flex-col items-center gap-2 py-12">
            <Terminal className="h-8 w-8 text-primary/10" />
            <p className="text-muted-foreground/50 text-sm">
              {recs.length === 0
                ? "No recommendations yet. A vulnerability scan must run first."
                : `No ${filter} severity findings.`}
            </p>
          </div>
        ) : (
          <div className="space-y-2.5">
            <AnimatePresence>
              {filtered.map((rec, i) => {
                const col = SEV_COLORS[rec.severity] ?? "#64748b";
                const copyKey = `${rec.cve}-${i}`;
                const pmColor = PKG_MGR_COLOR[rec.package_manager] ?? "#64748b";

                return (
                  <motion.div
                    key={copyKey}
                    initial={{ opacity: 0, x: -16 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.02 }}
                    className="rounded-xl border overflow-hidden"
                    style={{ borderColor: `${col}18`, background: `${col}04` }}
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between gap-3 p-4 pb-2">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span
                          className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                          style={{ color: col, background: `${col}15`, border: `1px solid ${col}25` }}
                        >
                          {rec.severity.toUpperCase()}
                        </span>
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded border"
                          style={{ color: "#00d4ff", borderColor: "#00d4ff25", background: "rgba(0,212,255,0.05)" }}>
                          {rec.cve}
                        </span>
                        <span
                          className="text-[10px] px-1.5 py-0.5 rounded border font-semibold"
                          style={{ color: pmColor, borderColor: `${pmColor}25`, background: `${pmColor}08` }}
                        >
                          {PKG_MGR_ICON[rec.package_manager] ?? "🔧"} {rec.package_manager}
                        </span>
                        <span className="flex items-center gap-1 text-[11px] text-foreground/60">
                          <Package className="h-3 w-3 text-muted-foreground/30" />
                          <code className="font-mono text-[10px]">{rec.package}</code>
                          <span className="text-muted-foreground/30 text-[10px]">{rec.installed_version}</span>
                        </span>
                        <span className="text-[9px] px-1 py-0.5 rounded bg-white/[0.03] text-muted-foreground/30 border border-white/[0.05] uppercase font-mono">
                          {rec.source}
                        </span>
                      </div>
                      {rec.can_auto_patch && (
                        <Badge className="bg-emerald-600/10 text-emerald-400/80 border border-emerald-500/15 text-[9px] shrink-0 h-5">
                          ✓ Auto-Patchable
                        </Badge>
                      )}
                    </div>

                    {/* Title */}
                    {rec.title && (
                      <p className="text-xs text-muted-foreground/50 px-4 pb-2 leading-relaxed">{rec.title}</p>
                    )}

                    {/* Fix command */}
                    <div className="mx-4 mb-3 rounded-lg p-3 flex items-center justify-between gap-2 border border-white/[0.06]" style={{ background: "hsl(228 20% 4% / 0.6)" }}>
                      <code className="text-[11px] text-emerald-400/80 font-mono break-all flex-1">{rec.fix_command}</code>
                      <button
                        onClick={() => copyCmd(rec.fix_command, copyKey)}
                        className="shrink-0 p-1.5 rounded-md hover:bg-white/5 transition"
                        title="Copy command"
                      >
                        {copied === copyKey
                          ? <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
                          : <Copy className="h-3.5 w-3.5 text-muted-foreground/30" />}
                      </button>
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-between px-4 pb-3 text-[10px] text-muted-foreground/30">
                      <span>
                        Fixed in: <code className="font-mono text-foreground/50">{rec.fixed_version}</code>
                      </span>
                      {rec.reference && (
                        <a
                          href={rec.reference}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center gap-1 text-blue-400/60 hover:text-blue-400/80 transition-colors"
                        >
                          Advisory <ExternalLink className="h-2.5 w-2.5" />
                        </a>
                      )}
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
