import { ReactNode, useEffect } from "react";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { Footer } from "./Footer";
import { ParticleBackground } from "@/components/effects/ParticleBackground";
import FloatingAIChatbox from "@/components/chat/FloatingAIChatbox";
import { motion, AnimatePresence } from "framer-motion";
import { useLocation } from "react-router-dom";

interface LayoutProps { children: ReactNode; }

const pageVariants = {
  initial:  { opacity: 0, y: 16, filter: "blur(4px)" },
  animate:  { opacity: 1, y: 0,  filter: "blur(0px)", transition: { duration: 0.35, ease: [0.22, 1, 0.36, 1] } },
  exit:     { opacity: 0, y: -8, filter: "blur(2px)", transition: { duration: 0.2,  ease: "easeIn" } },
};

/** Scroll to top whenever the route changes */
function ScrollReset() {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [pathname]);
  return null;
}

export function Layout({ children }: LayoutProps) {
  const { pathname } = useLocation();
  return (
    <div className="min-h-screen flex flex-col w-full bg-background relative">
      <ParticleBackground />
      <ScrollReset />
      <Header />
      <div className="flex flex-1 w-full relative z-10">
        <Sidebar />
        <main className="flex-1 overflow-y-auto relative z-10">
          <div className="max-w-[1400px] mx-auto px-5 py-6">
            <AnimatePresence mode="wait">
              <motion.div
                key={pathname}
                variants={pageVariants}
                initial="initial"
                animate="animate"
                exit="exit"
              >
                {children}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>
      <Footer />
      <FloatingAIChatbox />
    </div>
  );
}
