// Universal skeleton loader utility
import { motion } from "framer-motion";

interface SkeletonProps {
  className?: string;
}

export function Skeleton({ className = "" }: SkeletonProps) {
  return (
    <motion.div
      className={`rounded-lg bg-white/[0.03] relative overflow-hidden ${className}`}
      initial={{ opacity: 0.4 }}
      animate={{ opacity: [0.4, 0.6, 0.4] }}
      transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
    >
      <motion.div
        className="absolute inset-0 bg-gradient-to-r from-transparent via-white/[0.04] to-transparent"
        animate={{ x: ["-100%", "200%"] }}
        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
      />
    </motion.div>
  );
}

/** Pre-built skeleton layouts for common patterns */
export function SkeletonCard() {
  return (
    <div className="p-4 rounded-xl border border-white/[0.05] glass-elevated space-y-3">
      <div className="flex items-center justify-between">
        <Skeleton className="h-7 w-7 rounded-lg" />
        <Skeleton className="h-1.5 w-1.5 rounded-full" />
      </div>
      <Skeleton className="h-2.5 w-16" />
      <Skeleton className="h-6 w-14" />
      <Skeleton className="h-2 w-24" />
    </div>
  );
}

export function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 p-3.5 rounded-xl border border-white/[0.04]">
      <Skeleton className="h-3.5 w-3.5 rounded-full shrink-0" />
      <div className="flex-1 space-y-1.5">
        <Skeleton className="h-2.5 w-2/3" />
        <Skeleton className="h-2 w-1/2" />
      </div>
      <Skeleton className="h-4 w-14 rounded-full" />
      <Skeleton className="h-4 w-10 rounded" />
    </div>
  );
}

export function SkeletonStats() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
      {Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)}
    </div>
  );
}

export function SkeletonFeed({ rows = 6 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => <SkeletonRow key={i} />)}
    </div>
  );
}
