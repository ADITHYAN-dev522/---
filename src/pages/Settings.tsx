import { motion } from "framer-motion";
import { Card } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Settings as SettingsIcon, Bell, Shield, Database, Wifi } from "lucide-react";

export default function Settings() {
  return (
    <div className="space-y-5">
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col gap-1"
      >
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{
            background: "linear-gradient(135deg, #8b5cf6, #00d4ff, #10b981)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}
        >
          Settings
        </h1>
        <p className="text-sm text-muted-foreground/60">
          Configure system preferences and security policies
        </p>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <motion.div
          initial={{ opacity: 0, x: -16 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card className="glass-elevated p-5">
            <div className="flex items-center gap-3 mb-5">
              <div className="p-2 rounded-lg" style={{ background: "rgba(0,212,255,0.08)" }}>
                <Bell className="h-4 w-4 text-cyan-400/80" />
              </div>
              <h2 className="text-sm font-semibold">Notifications</h2>
            </div>

            <div className="space-y-3">
              {[
                "Email alerts for critical threats",
                "Push notifications for incidents",
                "Daily security summary report",
                "Slack integration",
              ].map((setting, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between py-2.5 border-b border-border/20 last:border-0"
                >
                  <Label htmlFor={`notif-${i}`} className="cursor-pointer text-[13px] text-foreground/80">
                    {setting}
                  </Label>
                  <Switch id={`notif-${i}`} defaultChecked={i < 2} />
                </div>
              ))}
            </div>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 16 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.15 }}
        >
          <Card className="glass-elevated p-5">
            <div className="flex items-center gap-3 mb-5">
              <div className="p-2 rounded-lg" style={{ background: "rgba(139,92,246,0.08)" }}>
                <Shield className="h-4 w-4 text-purple-400/80" />
              </div>
              <h2 className="text-sm font-semibold">Security Policies</h2>
            </div>

            <div className="space-y-4">
              <div>
                <Label htmlFor="retention" className="text-[12px] text-muted-foreground/60 uppercase tracking-wider">Log Retention Period (days)</Label>
                <Input
                  id="retention"
                  type="number"
                  defaultValue="90"
                  className="mt-1.5 bg-muted/20 border-border/30 focus:border-primary/30 rounded-lg h-9 text-sm"
                />
              </div>

              <div>
                <Label htmlFor="threshold" className="text-[12px] text-muted-foreground/60 uppercase tracking-wider">Threat Alert Threshold</Label>
                <Input
                  id="threshold"
                  defaultValue="Medium"
                  className="mt-1.5 bg-muted/20 border-border/30 focus:border-primary/30 rounded-lg h-9 text-sm"
                />
              </div>

              <div className="pt-1">
                <Button className="w-full h-9 text-xs rounded-lg bg-gradient-to-r from-cyan-600/80 to-purple-600/80 hover:from-cyan-600 hover:to-purple-600 border-0 transition-all">
                  Save Security Settings
                </Button>
              </div>
            </div>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="lg:col-span-2"
        >
          <Card className="glass-elevated p-5">
            <div className="flex items-center gap-3 mb-5">
              <div className="p-2 rounded-lg" style={{ background: "rgba(16,185,129,0.08)" }}>
                <Database className="h-4 w-4 text-emerald-400/80" />
              </div>
              <h2 className="text-sm font-semibold">Data Sources</h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {[
                { name: "Firewall Logs",      status: "Connected", events: "2.4M/day", color: "#10b981" },
                { name: "EDR Platform",        status: "Connected", events: "1.8M/day", color: "#10b981" },
                { name: "Cloud Security",      status: "Connected", events: "856K/day", color: "#10b981" },
                { name: "Network Traffic",     status: "Connected", events: "5.2M/day", color: "#10b981" },
                { name: "Email Gateway",       status: "Connected", events: "423K/day", color: "#10b981" },
                { name: "Identity Provider",   status: "Connected", events: "124K/day", color: "#10b981" },
              ].map((source, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.25 + i * 0.04 }}
                  whileHover={{ y: -2 }}
                  className="p-4 rounded-xl border border-border/20 bg-muted/10 relative overflow-hidden group cursor-default"
                >
                  <div
                    className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
                    style={{ background: `radial-gradient(circle at 20% 50%, ${source.color}08, transparent 65%)` }}
                  />
                  <div className="flex items-center gap-2 mb-2 relative z-10">
                    <Wifi className="h-3.5 w-3.5" style={{ color: source.color }} />
                    <h3 className="font-medium text-[13px]">{source.name}</h3>
                  </div>
                  <div className="flex items-center gap-1.5 relative z-10">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: source.color, boxShadow: `0 0 6px ${source.color}60` }} />
                    <span className="text-[10px] font-medium" style={{ color: source.color }}>{source.status}</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground/40 mt-1 relative z-10">{source.events}</p>
                  <div className="absolute bottom-0 left-0 right-0 h-[1px]" style={{ background: `linear-gradient(90deg, transparent, ${source.color}20, transparent)` }} />
                </motion.div>
              ))}
            </div>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
