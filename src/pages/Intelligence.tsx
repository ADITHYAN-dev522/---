import { motion } from "framer-motion";
import { Card } from "@/components/ui/card";
import { ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

/* =========================
   TYPES
   ========================= */
type WazuhAlert = {
  timestamp: string;
  severity: number;
  rule: string;
  agent: string;
  source: "wazuh";
};

export default function Intelligence() {
  const [alerts, setAlerts] = useState<WazuhAlert[]>([]);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [now, setNow] = useState(Date.now());

  /* =========================
     FETCH WAZUH ALERTS
     ========================= */
  async function fetchAlerts() {
    const res = await fetch(
      "/api/threat-intel/wazuh/alerts",
      { cache: "no-store" }
    );
    const data = await res.json();
    setAlerts(Array.isArray(data) ? data : []);
    setLastUpdated(Date.now());
  }

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 30_000); // auto-refresh
    return () => clearInterval(interval);
  }, []);

  /* =========================
     UPDATE TIMER
     ========================= */
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  /* =========================
     SEVERITY HEATMAP
     ========================= */
  const severityStats = useMemo(() => {
    const map: Record<number, number> = {};
    alerts.forEach((a) => {
      map[a.severity] = (map[a.severity] || 0) + 1;
    });
    return map;
  }, [alerts]);

  const secondsAgo =
    lastUpdated ? Math.floor((now - lastUpdated) / 1000) : null;

  return (
    <div className="space-y-6">
      {/* ================= HEADER ================= */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col gap-2"
      >
        <h1 className="text-3xl font-bold tracking-tight">
          Threat Intelligence (Live Wazuh)
        </h1>
        <p className="text-muted-foreground">
          Real-time host-based security alerts from Wazuh
        </p>
      </motion.div>

      {/* ================= LIVE STATUS ================= */}
      <div className="flex items-center gap-3 text-sm">
        <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
        <span className="text-green-400 font-medium">
          Live Wazuh Feed
        </span>
        {secondsAgo !== null && (
          <span className="text-muted-foreground">
            • Last updated {secondsAgo}s ago
          </span>
        )}
      </div>

      {/* ================= SEVERITY HEATMAP ================= */}
      <Card className="p-6">
        <h2 className="text-xl font-semibold mb-4">
          Alert Severity Heatmap
        </h2>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {[3, 5, 7, 9, 10].map((level) => (
            <div
              key={level}
              className="rounded-lg border p-4 flex flex-col items-center justify-center"
            >
              <p className="text-sm text-muted-foreground">
                Severity {level}
              </p>
              <p className="text-2xl font-bold">
                {severityStats[level] || 0}
              </p>
            </div>
          ))}
        </div>
      </Card>

      {/* ================= WAZUH ALERT FEED ================= */}
      <Card className="p-6">
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-red-500" />
          Live Security Alerts
        </h2>

        {alerts.length === 0 ? (
          <p className="text-muted-foreground">
            No alerts received from Wazuh yet.
          </p>
        ) : (
          <div className="space-y-3 max-h-[520px] overflow-y-auto pr-2">
            {alerts.map((alert, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="p-4 rounded-lg border bg-card hover:bg-card/80 transition"
              >
                <div className="flex justify-between items-start">
                  <div>
                    <p className="font-medium">{alert.rule}</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Agent: {alert.agent} • Source: {alert.source}
                    </p>
                  </div>
                  <span
                    className={`text-sm font-bold ${
                      alert.severity >= 9
                        ? "text-red-500"
                        : alert.severity >= 7
                        ? "text-orange-400"
                        : "text-yellow-400"
                    }`}
                  >
                    Sev {alert.severity}
                  </span>
                </div>

                <p className="text-xs text-muted-foreground mt-2">
                  {new Date(alert.timestamp).toLocaleString()}
                </p>
              </motion.div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
