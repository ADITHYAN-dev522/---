import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard, AlertTriangle, FileText, Brain,
  Zap, Settings, ChevronLeft, Bug, ShieldAlert,
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";

const navItems = [
  { icon: LayoutDashboard, label: "Dashboard",     path: "/",             accent: "#00d4ff", desc: "Overview & metrics" },
  { icon: AlertTriangle,   label: "Detections",    path: "/detections",   accent: "#f43f5e", desc: "Threat event feed"  },
  { icon: FileText,        label: "Incidents",     path: "/incidents",    accent: "#f97316", desc: "Incident tracker"   },
  { icon: Brain,           label: "Intelligence",  path: "/intelligence", accent: "#8b5cf6", desc: "Wazuh SIEM alerts"  },
  { icon: Bug,             label: "Malware",       path: "/malware",      accent: "#ef4444", desc: "ClamAV · YARA · VT" },
  { icon: ShieldAlert,     label: "Vulnerability", path: "/vulnerability",accent: "#eab308", desc: "Trivy · OSV · Semgrep"},
  { icon: Zap,             label: "Response",      path: "/response",     accent: "#10b981", desc: "PatchMaster patches" },
  { icon: Settings,        label: "Settings",      path: "/settings",     accent: "#64748b", desc: "Configuration"      },
];

/* Tooltip that appears next to collapsed icons */
function NavTooltip({ label, desc, color, visible }: { label: string; desc: string; color: string; visible: boolean }) {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, x: -8, scale: 0.95 }}
          animate={{ opacity: 1, x: 0, scale: 1 }}
          exit={{ opacity: 0, x: -6, scale: 0.95 }}
          transition={{ duration: 0.15 }}
          className="absolute left-[calc(100%+14px)] top-1/2 -translate-y-1/2 z-[200] pointer-events-none"
        >
          <div
            className="px-3 py-2.5 rounded-xl text-xs whitespace-nowrap"
            style={{
              background: "hsl(228 22% 6% / 0.97)",
              border: `1px solid ${color}30`,
              backdropFilter: "blur(16px)",
              boxShadow: `0 4px 20px hsl(228 20% 5% / 0.6), 0 0 20px ${color}10`,
            }}
          >
            <p className="font-semibold text-[11px]" style={{ color }}>{label}</p>
            <p className="text-muted-foreground text-[10px] mt-0.5 opacity-70">{desc}</p>
          </div>
          <div
            className="absolute left-0 top-1/2 -translate-y-1/2 -translate-x-[6px] w-2 h-2 rotate-45"
            style={{
              background: "hsl(228 22% 6%)",
              border: `1px solid ${color}20`,
              borderRight: "none",
              borderTop: "none",
            }}
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
      className={`sticky top-14 h-[calc(100vh-3.5rem)] glass-effect transition-all duration-300 relative overflow-visible flex flex-col ${
        collapsed ? "w-[56px]" : "w-[210px]"
      }`}
      style={{
        borderRight: "1px solid hsl(225 16% 13% / 0.5)",
      }}
    >
      {/* Left accent stripe */}
      <div
        className="absolute left-0 top-0 bottom-0 w-[1px] pointer-events-none"
        style={{
          background: "linear-gradient(to bottom, #00d4ff40, #8b5cf640, #10b98140, transparent)",
        }}
      />

      {/* Collapse toggle */}
      <div className="flex items-center justify-end p-2 shrink-0">
        <Button
          variant="ghost" size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className="h-7 w-7 text-muted-foreground/60 hover:text-foreground hover:bg-white/5 rounded-lg"
        >
          <motion.div animate={{ rotate: collapsed ? 180 : 0 }} transition={{ duration: 0.3 }}>
            <ChevronLeft className="h-3.5 w-3.5" />
          </motion.div>
        </Button>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-0.5 px-2 overflow-y-auto overflow-x-visible">
        {navItems.map((item, i) => (
          <div
            key={item.path}
            className="relative"
            onMouseEnter={() => collapsed && setHoveredIdx(i)}
            onMouseLeave={() => setHoveredIdx(null)}
          >
            <motion.div
              initial={{ x: -12, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ delay: 0.06 + i * 0.03 }}
            >
              <NavLink
                to={item.path}
                className={`flex items-center rounded-lg transition-all group relative overflow-hidden ${
                  collapsed ? "justify-center p-2.5" : "gap-3 px-3 py-2"
                } text-muted-foreground hover:text-foreground`}
                activeClassName="text-foreground bg-white/[0.06] font-medium"
              >
                {/* Active left indicator */}
                <motion.div
                  className="absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-r-full opacity-0 group-[.active]:opacity-100"
                  style={{ background: item.accent }}
                  layoutId="sidebar-indicator"
                />

                {/* Hover glow */}
                <div
                  className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-lg"
                  style={{
                    background: `radial-gradient(circle at 20% 50%, ${item.accent}08, transparent 70%)`,
                  }}
                />

                <motion.div
                  whileHover={{ scale: 1.15 }}
                  transition={{ type: "spring", stiffness: 400 }}
                  className="shrink-0 relative z-10"
                >
                  <item.icon
                    className="h-[16px] w-[16px] transition-all duration-200"
                    style={{ filter: "drop-shadow(0 0 0px transparent)" }}
                  />
                </motion.div>

                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity: 0, width: 0 }}
                      animate={{ opacity: 1, width: "auto" }}
                      exit={{ opacity: 0, width: 0 }}
                      transition={{ duration: 0.2 }}
                      className="truncate text-[13px] overflow-hidden whitespace-nowrap relative z-10"
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
      <div className="p-3 border-t border-border/30 shrink-0">
        <AnimatePresence mode="wait">
          {!collapsed ? (
            <motion.div key="full" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex items-center gap-2.5">
              <span
                className="h-2 w-2 rounded-full shrink-0 relative"
                style={{ background: online === null ? "#eab308" : online ? "#10b981" : "#ef4444" }}
              >
                {online && (
                  <motion.span
                    className="absolute inset-0 rounded-full"
                    animate={{ scale: [1, 2.5], opacity: [0.4, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity }}
                    style={{ background: "#10b981" }}
                  />
                )}
              </span>
              <div className="min-w-0">
                <p className="text-[10px] font-mono text-muted-foreground truncate">
                  {online === null ? "Connecting…" : online ? "Backend Online" : "Backend Offline"}
                </p>
                <p className="text-[9px] text-muted-foreground/30 font-mono">SentinelNexus v1.0</p>
              </div>
            </motion.div>
          ) : (
            <motion.div key="dot" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex justify-center">
              <span
                className="h-2 w-2 rounded-full"
                style={{ background: online === null ? "#eab308" : online ? "#10b981" : "#ef4444" }}
              />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.aside>
  );
}
