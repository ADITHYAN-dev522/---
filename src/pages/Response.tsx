import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Zap, CheckCircle, RefreshCw, Copy, Package, Terminal, AlertTriangle, Filter, ExternalLink } from "lucide-react";

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
  critical: "#FF1744",
  high:     "#FF6D00",
  medium:   "#FFC107",
  low:      "#00E676",
};

const SEV_BG: Record<string, string> = {
  critical: "rgba(255,23,68,0.10)",
  high:     "rgba(255,109,0,0.10)",
  medium:   "rgba(255,193,7,0.08)",
  low:      "rgba(0,230,118,0.07)",
};

const PKG_MGR_ICON: Record<string, string> = {
  pip:     "🐍",
  npm:     "📦",
  apt:     "🛡️",
  yum:     "🛡️",
  gem:     "💎",
  cargo:   "⚙️",
  go:      "🔵",
  unknown: "🔧",
};

const PKG_MGR_COLOR: Record<string, string> = {
  pip:     "#3B82F6",
  npm:     "#EF4444",
  apt:     "#8B5CF6",
  yum:     "#8B5CF6",
  gem:     "#EC4899",
  cargo:   "#F59E0B",
  go:      "#06B6D4",
  unknown: "#6B7280",
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

  // Filtered list
  const filtered = filter === "all" ? recs : recs.filter(r => r.severity === filter);

  // Stats
  const counts = {
    all:      recs.length,
    critical: recs.filter(r => r.severity === "critical").length,
    high:     recs.filter(r => r.severity === "high").length,
    medium:   recs.filter(r => r.severity === "medium").length,
    low:      recs.filter(r => r.severity === "low").length,
  };
  const autoCount = recs.filter(r => r.can_auto_patch).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-[#00D9FF] to-[#9D4EDD] bg-clip-text text-transparent">
          PatchMaster — Automated Response
        </h1>
        <p className="text-muted-foreground">
          CVE-mapped remediation commands generated from live vulnerability scan results
        </p>
      </motion.div>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Recommendations", value: recs.length,  color: "#00D9FF", icon: Zap },
          { label: "Auto-Patchable",        value: autoCount,    color: "#00E676", icon: CheckCircle },
          { label: "Critical Priority",     value: counts.critical, color: "#FF1744", icon: AlertTriangle },
          { label: "High Priority",         value: counts.high,  color: "#FF6D00", icon: AlertTriangle },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, scale: 0.93 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.08 }}>
            <Card className="p-5 bg-black/40 backdrop-blur-xl border text-center relative overflow-hidden group" style={{ borderColor: s.color + "30" }}>
              <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity" style={{ background: `linear-gradient(135deg, ${s.color}15, transparent)` }} />
              <s.icon className="h-6 w-6 mx-auto mb-2" style={{ color: s.color }} />
              <h3 className="text-3xl font-bold text-white">{s.value}</h3>
              <p className="text-xs text-muted-foreground mt-0.5">{s.label}</p>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Controls row */}
      <div className="flex items-center gap-3 flex-wrap">
        <Button variant="outline" onClick={fetchRecs} disabled={loading} className="gap-2">
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Loading…" : "Refresh"}
        </Button>
        {error && <p className="text-red-400 text-sm">{error}</p>}

        {/* Severity filter pills */}
        <div className="ml-auto flex items-center gap-1.5 flex-wrap">
          <Filter className="h-3.5 w-3.5 text-white/30" />
          {SEVERITY_ORDER.map(sev => {
            const col = sev === "all" ? "#9E9E9E" : SEV_COLORS[sev];
            const active = filter === sev;
            return (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className="px-3 py-1 rounded-full text-xs font-semibold border transition-all"
                style={{
                  borderColor: active ? col : `${col}40`,
                  background:  active ? `${col}20` : "transparent",
                  color:       active ? col : `${col}80`,
                }}
              >
                {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
                <span className="ml-1 opacity-70">
                  ({sev === "all" ? counts.all : counts[sev]})
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Remediation list */}
      <Card className="border-border p-6 bg-black/30 backdrop-blur-xl">
        <h2 className="text-xl font-semibold mb-5 flex items-center gap-2">
          <Terminal className="h-5 w-5 text-cyan-400" />
          Remediation Playbook
          <span className="text-sm text-white/30 font-normal ml-1">
            {filtered.length} of {recs.length} shown
          </span>
        </h2>

        {filtered.length === 0 && !loading ? (
          <p className="text-muted-foreground text-center py-10">
            {recs.length === 0
              ? "No recommendations yet. A vulnerability scan must run first."
              : `No ${filter} severity findings.`}
          </p>
        ) : (
          <div className="space-y-3">
            <AnimatePresence>
              {filtered.map((rec, i) => {
                const col = SEV_COLORS[rec.severity] ?? "#888";
                const bg  = SEV_BG[rec.severity] ?? "rgba(255,255,255,0.03)";
                const copyKey = `${rec.cve}-${i}`;
                const pmColor = PKG_MGR_COLOR[rec.package_manager] ?? "#6B7280";

                return (
                  <motion.div
                    key={copyKey}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.03 }}
                    className="rounded-xl border overflow-hidden"
                    style={{ borderColor: `${col}30`, background: bg }}
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between gap-4 p-4 pb-3">
                      <div className="flex flex-wrap items-center gap-2">
                        {/* Severity */}
                        <span
                          className="text-[11px] font-bold px-2 py-0.5 rounded"
                          style={{ color: col, background: `${col}20`, border: `1px solid ${col}40` }}
                        >
                          {rec.severity.toUpperCase()}
                        </span>
                        {/* CVE */}
                        <span className="font-mono text-xs px-2 py-0.5 rounded border"
                          style={{ color: "#00D9FF", borderColor: "#00D9FF40", background: "rgba(0,217,255,0.06)" }}>
                          {rec.cve}
                        </span>
                        {/* Package manager badge */}
                        <span
                          className="text-[11px] px-2 py-0.5 rounded border font-semibold"
                          style={{ color: pmColor, borderColor: `${pmColor}40`, background: `${pmColor}12` }}
                        >
                          {PKG_MGR_ICON[rec.package_manager] ?? "🔧"} {rec.package_manager}
                        </span>
                        {/* Package name */}
                        <span className="flex items-center gap-1 text-sm text-white/70">
                          <Package className="h-3 w-3 text-white/30" />
                          <code className="font-mono text-xs">{rec.package}</code>
                          <span className="text-white/30 text-xs">{rec.installed_version}</span>
                        </span>
                        {/* Source tag */}
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-white/30 border border-white/10 uppercase font-mono">
                          {rec.source}
                        </span>
                      </div>
                      {rec.can_auto_patch && (
                        <Badge className="bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 text-xs shrink-0">
                          ✓ Auto-Patchable
                        </Badge>
                      )}
                    </div>

                    {/* Title */}
                    {rec.title && (
                      <p className="text-sm text-white/60 px-4 pb-2 leading-relaxed">{rec.title}</p>
                    )}

                    {/* Fix command */}
                    <div className="mx-4 mb-3 bg-black/60 rounded-lg p-3 flex items-center justify-between gap-2 border border-white/10">
                      <code className="text-xs text-green-400 font-mono break-all flex-1">{rec.fix_command}</code>
                      <button
                        onClick={() => copyCmd(rec.fix_command, copyKey)}
                        className="shrink-0 p-1.5 rounded-md hover:bg-white/10 transition"
                        title="Copy command"
                      >
                        {copied === copyKey
                          ? <CheckCircle className="h-4 w-4 text-emerald-400" />
                          : <Copy className="h-4 w-4 text-white/30" />}
                      </button>
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-between px-4 pb-3 text-xs text-white/40">
                      <span>
                        Fixed in: <code className="font-mono text-white/60">{rec.fixed_version}</code>
                      </span>
                      {rec.reference && (
                        <a
                          href={rec.reference}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors"
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
