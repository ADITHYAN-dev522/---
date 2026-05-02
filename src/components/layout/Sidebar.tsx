import { motion } from "framer-motion";
import {
  LayoutDashboard, AlertTriangle, FileText, Brain,
  Zap, Settings, ChevronLeft, Bug, ShieldAlert,
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";

const navItems = [
  { icon: LayoutDashboard, label: "Dashboard",      path: "/",              accent: "#22D3EE" },
  { icon: AlertTriangle,   label: "Detections",     path: "/detections",    accent: "#F87171" },
  { icon: FileText,        label: "Incidents",      path: "/incidents",     accent: "#FB923C" },
  { icon: Brain,           label: "Intelligence",   path: "/intelligence",  accent: "#818CF8" },
  { icon: Bug,             label: "Malware",        path: "/malware",       accent: "#F87171" },
  { icon: ShieldAlert,     label: "Vulnerability",  path: "/vulnerability", accent: "#FBBF24" },
  { icon: Zap,             label: "Response",       path: "/response",      accent: "#34D399" },
  { icon: Settings,        label: "Settings",       path: "/settings",      accent: "#94A3B8" },
];

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    const check = () =>
      fetch("/api/health").then(r => setOnline(r.ok)).catch(() => setOnline(false));
    check();
    const id = setInterval(check, 15_000);
    return () => clearInterval(id);
  }, []);

  return (
    <motion.aside
      initial={{ x: -20, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ delay: 0.1 }}
      className={`sticky top-16 h-[calc(100vh-4rem)] border-r border-primary/15 glass-effect transition-all duration-300 relative overflow-hidden flex flex-col ${
        collapsed ? "w-16" : "w-60"
      }`}
    >
      {/* Left animated stripe */}
      <motion.div
        className="absolute left-0 top-0 bottom-0 w-[2px]"
        style={{ background: "linear-gradient(to bottom, #22D3EE, #38BDF8, #34D399, #22D3EE)" }}
        animate={{ backgroundPosition: ["0% 0%", "0% 100%", "0% 0%"] }}
        transition={{ duration: 5, repeat: Infinity, ease: "linear" }}
      />

      {/* Collapse toggle */}
      <div className="flex items-center justify-end p-3 border-b border-border/60 shrink-0">
        <Button variant="ghost" size="icon" onClick={() => setCollapsed(!collapsed)} className="h-8 w-8 text-muted-foreground hover:text-primary">
          <motion.div animate={{ rotate: collapsed ? 180 : 0 }} transition={{ duration: 0.25 }}>
            <ChevronLeft className="h-4 w-4" />
          </motion.div>
        </Button>
      </div>

      {/* Nav items */}
      <nav className="flex-1 space-y-0.5 p-2 overflow-y-auto">
        {navItems.map((item, i) => (
          <motion.div
            key={item.path}
            initial={{ x: -16, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ delay: 0.1 + i * 0.04 }}
          >
            <NavLink
              to={item.path}
              className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-muted-foreground transition-all hover:text-foreground hover:bg-white/5 relative group overflow-hidden"
              activeClassName="text-foreground font-medium bg-white/8"
            >
              {/* Active / hover left indicator */}
              <div
                className="absolute left-0 top-2 bottom-2 w-[3px] rounded-r-full opacity-0 group-hover:opacity-60 transition-opacity"
                style={{ background: item.accent }}
              />

              <motion.div
                whileHover={{ scale: 1.15 }}
                transition={{ type: "spring", stiffness: 400 }}
                className="relative z-10 shrink-0"
              >
                <item.icon
                  className="h-5 w-5 shrink-0 transition-colors"
                  style={{ color: "currentColor" }}
                />
              </motion.div>

              {!collapsed && (
                <motion.span
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="truncate relative z-10 text-sm"
                >
                  {item.label}
                </motion.span>
              )}
            </NavLink>
          </motion.div>
        ))}
      </nav>

      {/* Bottom status */}
      <div className="p-3 border-t border-border/60 shrink-0">
        {!collapsed ? (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-center gap-2">
            <span
              className="h-2 w-2 rounded-full shrink-0"
              style={{
                background: online === null ? "#FBBF24" : online ? "#34D399" : "#F87171",
                boxShadow: `0 0 6px ${online === null ? "#FBBF24" : online ? "#34D399" : "#F87171"}`,
              }}
            />
            <div className="min-w-0">
              <p className="text-xs font-mono text-muted-foreground truncate">
                {online === null ? "Checking…" : online ? "Backend Online" : "Backend Offline"}
              </p>
              <p className="text-[10px] text-muted-foreground/60">SentinelNexus v1.0</p>
            </div>
          </motion.div>
        ) : (
          <div className="flex justify-center">
            <span
              className="h-2 w-2 rounded-full"
              style={{ background: online === null ? "#FBBF24" : online ? "#34D399" : "#F87171" }}
            />
          </div>
        )}
      </div>
    </motion.aside>
  );
}
