import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldOff } from "lucide-react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error("404 Error: User attempted to access non-existent route:", location.pathname);
  }, [location.pathname]);

  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        className="text-center flex flex-col items-center gap-4"
      >
        <motion.div
          animate={{ rotate: [0, -5, 5, 0] }}
          transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
        >
          <ShieldOff className="h-16 w-16 text-primary/15" />
        </motion.div>
        <h1
          className="text-5xl font-bold tracking-tight"
          style={{
            background: "linear-gradient(135deg, #00d4ff, #8b5cf6)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}
        >
          404
        </h1>
        <p className="text-muted-foreground/50 text-sm max-w-xs">
          The page you're looking for doesn't exist or has been moved.
        </p>
        <a
          href="/"
          className="text-sm px-4 py-2 rounded-lg bg-primary/10 text-primary hover:bg-primary/20 transition-colors border border-primary/20"
        >
          Return to Dashboard
        </a>
      </motion.div>
    </div>
  );
};

export default NotFound;
