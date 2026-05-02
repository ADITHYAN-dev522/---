import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard, AlertTriangle, FileText, Brain,
  Zap, Settings, ChevronLeft, Bug, ShieldAlert,
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";

const navItems = [
  { icon: LayoutDashboard, label: "Dashboard",     path: "/",             accent: "#22D3EE", desc: "Overview & metrics" },
  { icon: AlertTriangle,   label: "Detections",    path: "/detections",   accent: "#F87171", desc: "Threat event feed"  },
  { icon: FileText,        label: "Incidents",     path: "/incidents",    accent: "#FB923C", desc: "Incident tracker"   },
  { icon: Brain,           label: "Intelligence",  path: "/intelligence", accent: "#818CF8", desc: "Wazuh SIEM alerts"  },
  { icon: Bug,             label: "Malware",       path: "/malware",      accent: "#F87171", desc: "ClamAV · YARA · VT" },
  { icon: ShieldAlert,     label: "Vulnerability", path: "/vulnerability",accent: "#FBBF24", desc: "Trivy · OSV · Semgrep"},
  { icon: Zap,             label: "Response",      path: "/response",     accent: "#34D399", desc: "PatchMaster patches" },
  { icon: Settings,        label: "Settings",      path: "/settings",     accent: "#94A3B8", desc: "Configuration"      },
];

/* Tooltip that appears next to collapsed icons */
function NavTooltip({ label, desc, color, visible }: { label: string; desc: string; color: string; visible: boolean }) {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, x: -6 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -4 }}
          transition={{ duration: 0.15 }}
          className="absolute left-[calc(100%+12px)] top-1/2 -translate-y-1/2 z-[200] pointer-events-none"
        >
          <div
            className="px-3 py-2 rounded-xl text-xs whitespace-nowrap shadow-2xl"
            style={{
              background: "hsl(220 16% 9% / 0.97)",
              border: `1px solid ${color}40`,
              backdropFilter: "blur(12px)",
            }}
          >
            <p className="font-semibold" style={{ color }}>{label}</p>
            <p className="text-muted-foreground text-[10px] mt-0.5">{desc}</p>
          </div>
          {/* Arrow */}
          <div
            className="absolute left-0 top-1/2 -translate-y-1/2 -translate-x-[7px] w-2 h-2 rotate-45"
            style={{ background: "hsl(220 16% 9%)", border: `1px solid ${color}30`, borderRight: "none", borderTop: "none" }}
          />
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [online,    setOnline]    = useState<boolean | null>(null);
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  useEffect(() => {
    const check = () => fetch("/api/health").then(r => setOnline(r.ok)).catch(() => setOnline(false));
    check();
    const id = setInterval(check, 15_000);
    return () => clearInterval(id);
  }, []);

  return (
    <motion.aside
      initial={{ x: -20, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ delay: 0.1 }}
      className={`sticky top-16 h-[calc(100vh-4rem)] border-r border-primary/15 glass-effect transition-all duration-300 relative overflow-visible flex flex-col ${
        collapsed ? "w-[60px]" : "w-[220px]"
      }`}
    >
      {/* Left animated stripe */}
      <div
        className="absolute left-0 top-0 bottom-0 w-[2px] pointer-events-none"
        style={{ background: "linear-gradient(to bottom, #22D3EE 0%, #38BDF8 33%, #818CF8 66%, #34D399 100%)" }}
      />

      {/* Collapse toggle */}
      <div className="flex items-center justify-end p-2.5 border-b border-border/40 shrink-0">
        <Button
          variant="ghost" size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className="h-7 w-7 text-muted-foreground hover:text-foreground hover:bg-white/5"
        >
          <motion.div animate={{ rotate: collapsed ? 180 : 0 }} transition={{ duration: 0.25 }}>
            <ChevronLeft className="h-4 w-4" />
          </motion.div>
        </Button>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-0.5 p-2 overflow-y-auto overflow-x-visible">
        {navItems.map((item, i) => (
          <div
            key={item.path}
            className="relative"
            onMouseEnter={() => collapsed && setHoveredIdx(i)}
            onMouseLeave={() => setHoveredIdx(null)}
          >
            <motion.div
              initial={{ x: -16, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ delay: 0.08 + i * 0.04 }}
            >
              <NavLink
                to={item.path}
                className={`flex items-center rounded-xl transition-all group relative overflow-hidden ${
                  collapsed ? "justify-center p-2.5" : "gap-3 px-3 py-2.5"
                } text-muted-foreground hover:text-foreground hover:bg-white/5`}
                activeClassName="text-foreground bg-white/8 font-medium"
              >
                {/* Active left bar */}
                <div
                  className="absolute left-0 top-2 bottom-2 w-[3px] rounded-r-full scale-y-0 group-[.active]:scale-y-100 transition-transform origin-center"
                  style={{ background: item.accent }}
                />

                <motion.div
                  whileHover={{ scale: 1.15 }}
                  transition={{ type: "spring", stiffness: 400 }}
                  className="shrink-0"
                >
                  <item.icon
                    className="h-[18px] w-[18px] transition-colors group-hover:drop-shadow-[0_0_6px_currentColor]"
                  />
                </motion.div>

                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity: 0, width: 0 }}
                      animate={{ opacity: 1, width: "auto" }}
                      exit={{ opacity: 0, width: 0 }}
                      transition={{ duration: 0.2 }}
                      className="truncate text-sm overflow-hidden whitespace-nowrap"
                    >
                      {item.label}
                    </motion.span>
                  )}
                </AnimatePresence>
              </NavLink>
            </motion.div>

            {/* Tooltip (collapsed only) */}
            {collapsed && (
              <NavTooltip
                label={item.label}
                desc={item.desc}
                color={item.accent}
                visible={hoveredIdx === i}
              />
            )}
          </div>
        ))}
      </nav>

      {/* Status footer */}
      <div className="p-3 border-t border-border/40 shrink-0">
        <AnimatePresence mode="wait">
          {!collapsed ? (
            <motion.div key="full" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex items-center gap-2.5">
              <span
                className="h-2 w-2 rounded-full shrink-0 relative"
                style={{ background: online === null ? "#FBBF24" : online ? "#34D399" : "#F87171" }}
              >
                {online && (
                  <motion.span
                    className="absolute inset-0 rounded-full"
                    animate={{ scale: [1, 2.5], opacity: [0.5, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity }}
                    style={{ background: "#34D399" }}
                  />
                )}
              </span>
              <div className="min-w-0">
                <p className="text-[11px] font-mono text-muted-foreground truncate">
                  {online === null ? "Checking…" : online ? "Backend Online" : "Backend Offline"}
                </p>
                <p className="text-[9px] text-muted-foreground/40">SentinelNexus v1.0</p>
              </div>
            </motion.div>
          ) : (
            <motion.div key="dot" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex justify-center">
              <span
                className="h-2 w-2 rounded-full"
                style={{ background: online === null ? "#FBBF24" : online ? "#34D399" : "#F87171" }}
              />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.aside>
  );
}
