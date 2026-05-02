import { useState } from "react";
import { Search, Bell, Shield } from "lucide-react";
import { motion } from "framer-motion";
import { Input } from "@/components/ui/input";

export function Header() {
  const [searchFocused, setSearchFocused] = useState(false);
  const [notif, setNotif] = useState(true);

  return (
    <motion.header
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      className="sticky top-0 z-50 border-b border-primary/15 glass-effect relative overflow-hidden"
    >
      {/* Animated gradient top line */}
      <div
        className="absolute top-0 left-0 right-0 h-[2px]"
        style={{ background: "linear-gradient(90deg, #22D3EE, #38BDF8, #34D399, #22D3EE)", backgroundSize: "200% 100%" }}
      />
      <style>{`@keyframes hdr-grad{0%{background-position:0% 50%}100%{background-position:200% 50%}}`}</style>
      <div className="absolute top-0 left-0 right-0 h-[2px] animate-[hdr-grad_3s_linear_infinite]" style={{background:"linear-gradient(90deg,#22D3EE,#38BDF8,#818CF8,#34D399,#22D3EE)",backgroundSize:"200% 100%"}}/>

      <div className="flex h-16 items-center justify-between px-6 relative z-10">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <motion.div whileHover={{ scale: 1.1 }} transition={{ type: "spring", stiffness: 300 }}>
            <Shield className="h-7 w-7" style={{ color: "#22D3EE", filter: "drop-shadow(0 0 8px #22D3EE80)" }} />
          </motion.div>
          <div>
            <motion.h1
              className="text-xl font-bold tracking-tight"
              style={{
                background: "linear-gradient(90deg, #22D3EE, #38BDF8, #34D399)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }}
            >
              SentinelNexus
            </motion.h1>
            <p className="text-[10px] text-muted-foreground font-mono -mt-0.5">AI-Powered SOC Platform</p>
          </div>
        </div>

        {/* Search + Bell */}
        <div className="flex items-center gap-3">
          <motion.div
            animate={{ width: searchFocused ? 320 : 220 }}
            transition={{ duration: 0.25, type: "spring", stiffness: 250 }}
            className="relative"
          >
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground z-10" />
            <Input
              placeholder="Search detections, incidents…"
              className="pl-8 h-9 text-sm glass-effect border-primary/20 focus:border-primary/50 focus:ring-0 transition-all"
              onFocus={() => setSearchFocused(true)}
              onBlur={() => setSearchFocused(false)}
            />
          </motion.div>

          <button
            onClick={() => setNotif(n => !n)}
            className="relative p-2 rounded-lg border border-border/60 glass-effect hover:border-primary/30 transition-colors"
          >
            <Bell className="h-4 w-4 text-muted-foreground" />
            {notif && (
              <motion.span
                className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full"
                animate={{ scale: [1, 1.3, 1] }}
                transition={{ duration: 2, repeat: Infinity }}
                style={{ background: "#F87171", boxShadow: "0 0 6px #F87171" }}
              />
            )}
          </button>
        </div>
      </div>
    </motion.header>
  );
}
