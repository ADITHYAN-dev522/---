import { useState, useEffect } from "react";
import { Search, Bell, Shield, Command } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { Input } from "@/components/ui/input";

export function Header() {
  const [searchFocused, setSearchFocused] = useState(false);
  const [notif, setNotif] = useState(true);
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <motion.header
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      className="sticky top-0 z-50 glass-elevated relative overflow-hidden"
    >
      {/* Animated gradient top line */}
      <div
        className="absolute top-0 left-0 right-0 h-[1px]"
        style={{
          background: "linear-gradient(90deg, transparent, #00d4ff, #7c3aed, #00d4ff, transparent)",
          backgroundSize: "300% 100%",
          animation: "border-flow 4s linear infinite",
        }}
      />

      <div className="flex h-14 items-center justify-between px-5 relative z-10">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <motion.div
            whileHover={{ scale: 1.1, rotate: 5 }}
            transition={{ type: "spring", stiffness: 300 }}
            className="relative"
          >
            <Shield
              className="h-7 w-7"
              style={{
                color: "#00d4ff",
                filter: "drop-shadow(0 0 10px rgba(0,212,255,0.5))",
              }}
            />
            {/* Shield pulse ring */}
            <motion.div
              className="absolute inset-0 rounded-full"
              animate={{ scale: [1, 1.8], opacity: [0.3, 0] }}
              transition={{ duration: 2, repeat: Infinity }}
              style={{ border: "1px solid #00d4ff" }}
            />
          </motion.div>
          <div>
            <h1
              className="text-lg font-bold tracking-tight"
              style={{
                background: "linear-gradient(135deg, #00d4ff 0%, #7c3aed 50%, #06d6a0 100%)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }}
            >
              SentinelNexus
            </h1>
            <p className="text-[9px] text-muted-foreground font-mono -mt-0.5 tracking-widest uppercase opacity-60">
              Threat Defense Platform
            </p>
          </div>
        </div>

        {/* Center: Time display */}
        <div className="hidden md:flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg glass-effect">
            <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[11px] font-mono text-muted-foreground">
              {time.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" })}
            </span>
            <span className="text-[11px] font-mono text-primary/80">
              {time.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
            </span>
          </div>
        </div>

        {/* Right: Search + Bell */}
        <div className="flex items-center gap-2">
          <motion.div
            animate={{ width: searchFocused ? 300 : 200 }}
            transition={{ duration: 0.3, type: "spring", stiffness: 300 }}
            className="relative hidden sm:block"
          >
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground/60 z-10" />
            <Input
              placeholder="Search threats…"
              className="pl-8 pr-10 h-8 text-xs glass-effect border-transparent focus:border-primary/30 focus:ring-0 rounded-lg placeholder:text-muted-foreground/40"
              onFocus={() => setSearchFocused(true)}
              onBlur={() => setSearchFocused(false)}
            />
            <kbd className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-mono text-muted-foreground/40 border border-border/40 bg-muted/30">
              <Command className="h-2.5 w-2.5" />K
            </kbd>
          </motion.div>

          <button
            onClick={() => setNotif(n => !n)}
            className="relative p-2 rounded-lg glass-effect hover:bg-white/5 transition-all group"
          >
            <Bell className="h-4 w-4 text-muted-foreground group-hover:text-foreground transition-colors" />
            <AnimatePresence>
              {notif && (
                <motion.span
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  exit={{ scale: 0 }}
                  className="absolute -top-0.5 -right-0.5 h-2.5 w-2.5 rounded-full flex items-center justify-center"
                  style={{
                    background: "linear-gradient(135deg, #f43f5e, #ef4444)",
                    boxShadow: "0 0 8px rgba(239,68,68,0.6)",
                  }}
                >
                  <motion.span
                    className="absolute inset-0 rounded-full"
                    animate={{ scale: [1, 2], opacity: [0.4, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity }}
                    style={{ background: "#ef4444" }}
                  />
                </motion.span>
              )}
            </AnimatePresence>
          </button>
        </div>
      </div>
    </motion.header>
  );
}
