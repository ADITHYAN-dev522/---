import { ReactNode } from "react";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { Footer } from "./Footer";
import { ParticleBackground } from "@/components/effects/ParticleBackground";
import FloatingAIChatbox from "@/components/chat/FloatingAIChatbox";
import { motion, AnimatePresence } from "framer-motion";
import { useLocation } from "react-router-dom";

interface LayoutProps { children: ReactNode; }

const pageVariants = {
  initial:  { opacity: 0, y: 12 },
  animate:  { opacity: 1, y: 0,  transition: { duration: 0.25, ease: "easeOut" } },
  exit:     { opacity: 0, y: -8, transition: { duration: 0.15, ease: "easeIn"  } },
};

export function Layout({ children }: LayoutProps) {
  const { pathname } = useLocation();
  return (
    <div className="min-h-screen flex flex-col w-full bg-background relative">
      <ParticleBackground />
      <Header />
      <div className="flex flex-1 w-full relative z-10">
        <Sidebar />
        <main className="flex-1 overflow-y-auto relative z-10">
          <div className="container mx-auto p-6">
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
