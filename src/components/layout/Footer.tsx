import { motion } from "framer-motion";
import { Shield } from "lucide-react";

export function Footer() {
  return (
    <motion.footer
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.3 }}
      className="relative z-10 border-t border-border/30"
      style={{
        background: "hsl(228 22% 4% / 0.8)",
        backdropFilter: "blur(12px)",
      }}
    >
      <div className="flex h-10 items-center justify-center gap-2 px-6">
        <Shield className="h-3 w-3 text-primary/30" />
        <p className="text-[10px] text-muted-foreground/50 font-mono tracking-wider">
          SentinelNexus v1.0 · AI-Powered SOC Platform · © 2026
        </p>
      </div>
    </motion.footer>
  );
}
