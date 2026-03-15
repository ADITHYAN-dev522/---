import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Zap, CheckCircle, RefreshCw, Copy, Package, Terminal, AlertTriangle } from "lucide-react";

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

const SEV_COLORS: Record<string, string> = {
  critical: "#FF1744",
  high:     "#FF6D00",
  medium:   "#FFC107",
  low:      "#00E676",
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

export default function Response() {
  const [recs, setRecs]       = useState<Recommendation[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [copied, setCopied]   = useState<string | null>(null);

  const fetchRecs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("http://localhost:8000/api/patchmaster/recommendations?limit=50", { cache: "no-store" });
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

  const copyToClipboard = (cmd: string, cve: string) => {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopied(cve);
      setTimeout(() => setCopied(null), 2000);
    });
  };

  const autoCount = recs.filter(r => r.can_auto_patch).length;
  const critCount = recs.filter(r => r.severity === "critical").length;

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-[#00D9FF] to-[#9D4EDD] bg-clip-text text-transparent">
          PatchMaster — Automated Response
        </h1>
        <p className="text-muted-foreground">CVE-mapped remediation commands generated from your vulnerability scan results</p>
      </motion.div>

      {/* ── Stats ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: "Total Recommendations", value: recs.length,  color: "#00D9FF", icon: Zap },
          { label: "Auto-Patchable",        value: autoCount,    color: "#00E676", icon: CheckCircle },
          { label: "Critical Priority",     value: critCount,    color: "#FF1744", icon: AlertTriangle },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.1 }}>
            <Card className="p-6 bg-black/40 backdrop-blur-xl border text-center" style={{ borderColor: s.color + "30" }}>
              <s.icon className="h-8 w-8 mx-auto mb-3" style={{ color: s.color }} />
              <h3 className="text-3xl font-bold text-white">{s.value}</h3>
              <p className="text-sm text-muted-foreground">{s.label}</p>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* ── Refresh __ */}
      <div className="flex items-center gap-3">
        <Button variant="outline" onClick={fetchRecs} disabled={loading} className="gap-2">
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Loading…" : "Refresh"}
        </Button>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {/* ── Recommendations list __ */}
      <Card className="border-border p-6">
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <Terminal className="h-5 w-5 text-cyan-400" /> Remediation Playbook
        </h2>

        {recs.length === 0 && !loading ? (
          <p className="text-muted-foreground text-center py-8">
            No recommendations yet. A vulnerability scan must run first.
          </p>
        ) : (
          <div className="space-y-4">
            <AnimatePresence>
              {recs.map((rec, i) => (
                <motion.div key={`${rec.cve}-${i}`} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }}
                  className="p-4 rounded-lg border bg-card/50" style={{ borderColor: (SEV_COLORS[rec.severity] ?? "#888") + "40" }}>
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge style={{ backgroundColor: SEV_COLORS[rec.severity] }} className="font-bold text-xs">
                        {rec.severity.toUpperCase()}
                      </Badge>
                      <Badge variant="outline" className="font-mono text-xs">{rec.cve}</Badge>
                      <span className="text-sm">{PKG_MGR_ICON[rec.package_manager] ?? "🔧"}</span>
                      <span className="flex items-center gap-1 text-sm">
                        <Package className="h-3 w-3" />
                        <span className="font-mono">{rec.package}</span>
                        <span className="text-muted-foreground text-xs">{rec.installed_version}</span>
                      </span>
                    </div>
                    {rec.can_auto_patch && (
                      <Badge className="bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 text-xs shrink-0">
                        Auto-Patchable
                      </Badge>
                    )}
                  </div>

                  {rec.title && <p className="text-sm text-muted-foreground mb-3">{rec.title}</p>}

                  {/* Fix command */}
                  <div className="bg-black/60 rounded-md p-3 flex items-center justify-between gap-2 border border-white/10">
                    <code className="text-xs text-green-400 font-mono break-all flex-1">{rec.fix_command}</code>
                    <button
                      onClick={() => copyToClipboard(rec.fix_command, rec.cve)}
                      className="shrink-0 p-1.5 rounded-md hover:bg-white/10 transition"
                      title="Copy command"
                    >
                      {copied === rec.cve
                        ? <CheckCircle className="h-4 w-4 text-emerald-400" />
                        : <Copy className="h-4 w-4 text-muted-foreground" />}
                    </button>
                  </div>

                  <div className="flex items-center justify-between mt-2">
                    <span className="text-xs text-muted-foreground">
                      Fixed in: <span className="font-mono">{rec.fixed_version}</span>
                    </span>
                    {rec.reference && (
                      <a href={rec.reference} target="_blank" rel="noreferrer"
                        className="text-xs text-blue-400 hover:underline">
                        View advisory ↗
                      </a>
                    )}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </Card>
    </div>
  );
}
