import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { MessageCircle, X, Send, Sparkles, Pin, PinOff, Trash2, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

export default function FloatingAIChatbox() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "1",
      role: "assistant",
      content:
        "👋 I'm your **AI Security Analyst**. I can help you analyze threats, explain vulnerability findings, and provide remediation guidance.\n\n📌 **Tip:** Use the **Pin Data** button to attach scan results, CVE details, or any text — then ask me about it!",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [pinnedData, setPinnedData] = useState<string>("");
  const [showPinInput, setShowPinInput] = useState(false);
  const [pinDraft, setPinDraft] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll on new messages
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, loading]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: "user",
      content: input,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    const messageToSend = input;
    setInput("");
    setLoading(true);

    try {
      // Fetch latest scan context
      let latestScan: any = {};
      try {
        const r = await fetch("http://localhost:8000/api/scan/results");
        latestScan = await r.json();
      } catch (_) {}

      // Build context — merge live scan + any pinned data
      const context: any = { ...latestScan };
      if (pinnedData.trim()) {
        context.pinned_analyst_data = pinnedData;
      }

      const res = await fetch("http://localhost:8000/api/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: messageToSend, context }),
      });

      const data = await res.json();
      const aiMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: data.reply || "No response generated.",
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, aiMessage]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          id: (Date.now() + 2).toString(),
          role: "assistant",
          content:
            "⚠️ AI backend is unreachable. Make sure your backend is running (`uvicorn main:app --reload` in the backend directory).",
          timestamp: new Date(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handlePinData = () => {
    if (pinDraft.trim()) {
      setPinnedData(pinDraft.trim());
      setShowPinInput(false);
      setPinDraft("");
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now().toString(),
          role: "assistant",
          content: `📌 Data pinned! I'll use this as context for your questions:\n\n\`\`\`\n${pinDraft.trim().slice(0, 300)}${pinDraft.length > 300 ? "\n…(truncated)" : ""}\n\`\`\`\n\nAsk me anything about it!`,
          timestamp: new Date(),
        },
      ]);
    }
  };

  const handleUnpin = () => {
    setPinnedData("");
    setMessages((prev) => [
      ...prev,
      {
        id: Date.now().toString(),
        role: "assistant",
        content: "📌 Pinned data cleared. I'm now using only live scan context.",
        timestamp: new Date(),
      },
    ]);
  };

  // Render markdown-like content (bold, code)
  function renderContent(text: string) {
    const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|\n)/g);
    return parts.map((part, i) => {
      if (part.startsWith("**") && part.endsWith("**"))
        return <strong key={i}>{part.slice(2, -2)}</strong>;
      if (part.startsWith("`") && part.endsWith("`") && part.length > 2)
        return <code key={i} className="bg-white/10 px-1 rounded text-[11px] font-mono">{part.slice(1, -1)}</code>;
      if (part === "\n") return <br key={i} />;
      // Code block
      if (part.startsWith("```") && part.endsWith("```"))
        return <pre key={i} className="bg-black/40 rounded p-2 text-xs font-mono mt-1 whitespace-pre-wrap break-all">{part.slice(3, -3)}</pre>;
      return <span key={i}>{part}</span>;
    });
  }

  return (
    <>
      {/* Floating trigger button */}
      <AnimatePresence>
        {!isOpen && (
          <motion.div
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            className="fixed bottom-8 right-8 z-50"
          >
            <Button
              onClick={() => setIsOpen(true)}
              className="relative h-16 w-16 rounded-full bg-gradient-to-br from-[#9D4EDD] via-[#FF1744] to-[#00D9FF] p-0 shadow-2xl hover:scale-110 transition-transform"
              style={{ boxShadow: "0 0 40px rgba(157,78,221,0.6), 0 0 80px rgba(0,217,255,0.4)" }}
            >
              <motion.div
                className="absolute inset-0 rounded-full bg-gradient-to-br from-[#9D4EDD] via-[#FF1744] to-[#00D9FF] opacity-50 blur-xl"
                animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0.8, 0.5] }}
                transition={{ duration: 2, repeat: Infinity }}
              />
              <MessageCircle className="relative h-8 w-8 text-white" />
              {/* Online indicator */}
              <motion.div
                className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-[#00E676]"
                animate={{ scale: [1, 1.3, 1] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              />
              {/* Pinned data indicator */}
              {pinnedData && (
                <motion.div
                  className="absolute -bottom-1 -left-1 w-4 h-4 rounded-full bg-[#FFC107] flex items-center justify-center"
                  animate={{ scale: [1, 1.2, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  <Pin className="w-2 h-2 text-black" />
                </motion.div>
              )}
            </Button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Chat window */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            className="fixed bottom-8 right-8 z-50 w-[440px] rounded-2xl border-2 border-[#9D4EDD]/50 bg-black/95 backdrop-blur-xl shadow-2xl overflow-hidden flex flex-col"
            style={{
              maxHeight: "600px",
              minHeight: "400px",
              boxShadow: "0 0 60px rgba(157,78,221,0.4), inset 0 0 60px rgba(0,217,255,0.05)",
            }}
          >
            {/* Header */}
            <div className="relative border-b border-[#9D4EDD]/30 bg-gradient-to-r from-[#9D4EDD]/20 to-[#00D9FF]/20 p-4 shrink-0">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <motion.div animate={{ rotate: 360 }} transition={{ duration: 8, repeat: Infinity, ease: "linear" }}>
                    <Sparkles className="h-5 w-5 text-[#9D4EDD]" />
                  </motion.div>
                  <div>
                    <h3 className="font-semibold text-white text-sm">AI Security Analyst</h3>
                    <div className="flex items-center gap-2">
                      <motion.div
                        className="w-2 h-2 rounded-full bg-[#00E676]"
                        animate={{ opacity: [1, 0.5, 1] }}
                        transition={{ duration: 2, repeat: Infinity }}
                      />
                      <p className="text-xs text-white/60">{loading ? "Thinking…" : "Online"}</p>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  {/* Pin data button */}
                  <Button
                    variant="ghost" size="sm"
                    onClick={() => setShowPinInput(s => !s)}
                    className="h-8 px-2 text-xs hover:bg-white/10 gap-1.5"
                    title={pinnedData ? "Pinned data active" : "Pin data to context"}
                    style={{ color: pinnedData ? "#FFC107" : "rgba(255,255,255,0.4)" }}
                  >
                    <Pin className="h-3.5 w-3.5" />
                    {pinnedData ? "Pinned" : "Pin"}
                  </Button>
                  {pinnedData && (
                    <Button variant="ghost" size="sm" onClick={handleUnpin}
                      className="h-8 w-8 p-0 hover:bg-white/10 text-white/30 hover:text-red-400" title="Unpin data">
                      <PinOff className="h-3.5 w-3.5" />
                    </Button>
                  )}
                  <Button variant="ghost" size="sm"
                    onClick={() => setMessages(msgs => [msgs[0]])}
                    className="h-8 w-8 p-0 hover:bg-white/10 text-white/30" title="Clear chat">
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setIsOpen(false)}
                    className="h-8 w-8 p-0 hover:bg-white/10">
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              {/* Pin data input panel */}
              <AnimatePresence>
                {showPinInput && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="mt-3 overflow-hidden"
                  >
                    <p className="text-xs text-white/50 mb-1.5">
                      📌 Paste any data (CVE details, scan output, log lines) to pin to context:
                    </p>
                    <textarea
                      value={pinDraft}
                      onChange={e => setPinDraft(e.target.value)}
                      placeholder="Paste scan output, CVE details, log entries, or anything you want me to analyze…"
                      className="w-full text-xs bg-white/5 border border-white/20 rounded-lg p-2 text-white placeholder:text-white/30 resize-none focus:outline-none focus:border-[#9D4EDD]/60"
                      rows={4}
                    />
                    <div className="flex gap-2 mt-1.5">
                      <Button size="sm" onClick={handlePinData}
                        className="text-xs h-7 bg-[#9D4EDD]/80 hover:bg-[#9D4EDD] text-white flex-1">
                        <Pin className="w-3 h-3 mr-1" /> Pin to Context
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setShowPinInput(false)}
                        className="text-xs h-7 hover:bg-white/10 text-white/50">
                        <ChevronDown className="w-3 h-3" />
                      </Button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Pinned data indicator bar */}
            {pinnedData && !showPinInput && (
              <div className="px-4 py-1.5 bg-[#FFC107]/10 border-b border-[#FFC107]/20 flex items-center gap-2">
                <Pin className="w-3 h-3 text-[#FFC107] shrink-0" />
                <p className="text-[11px] text-[#FFC107]/80 truncate">
                  Pinned: {pinnedData.slice(0, 80)}{pinnedData.length > 80 ? "…" : ""}
                </p>
              </div>
            )}

            {/* Messages */}
            <div
              ref={scrollRef}
              className="flex-1 overflow-y-auto p-4 space-y-3 min-h-0"
              style={{ scrollbarWidth: "thin", scrollbarColor: "rgba(157,78,221,0.3) transparent" }}
            >
              {messages.map((msg) => (
                <motion.div
                  key={msg.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                >
                  <div
                    className={`max-w-[85%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${
                      msg.role === "user"
                        ? "bg-gradient-to-br from-[#9D4EDD] to-[#FF1744] text-white"
                        : "bg-white/5 border border-[#00D9FF]/20 text-white"
                    }`}
                    style={{
                      boxShadow:
                        msg.role === "assistant"
                          ? "0 0 20px rgba(0,217,255,0.12)"
                          : "0 0 20px rgba(157,78,221,0.25)",
                    }}
                  >
                    <div>{renderContent(msg.content)}</div>
                    <p className="text-[10px] mt-1.5 opacity-50">
                      {msg.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                    </p>
                  </div>
                </motion.div>
              ))}

              {/* Typing indicator */}
              {loading && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex justify-start">
                  <div className="bg-white/5 border border-[#00D9FF]/20 rounded-2xl px-4 py-3 flex items-center gap-1.5">
                    {[0, 0.2, 0.4].map((delay, i) => (
                      <motion.div key={i}
                        className="w-2 h-2 rounded-full bg-[#00D9FF]/60"
                        animate={{ y: [0, -4, 0] }}
                        transition={{ duration: 0.7, delay, repeat: Infinity }}
                      />
                    ))}
                  </div>
                </motion.div>
              )}
            </div>

            {/* Input bar */}
            <div className="border-t border-[#9D4EDD]/30 bg-black/60 backdrop-blur-sm p-4 shrink-0">
              <div className="flex items-center gap-2">
                <Input
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && handleSend()}
                  placeholder="Ask about vulnerabilities, threats, or paste data…"
                  className="flex-1 bg-white/5 border-white/20 focus:border-[#9D4EDD]/60 text-white placeholder:text-white/30 text-sm"
                  disabled={loading}
                />
                <Button
                  onClick={handleSend}
                  disabled={loading || !input.trim()}
                  size="sm"
                  className="h-10 w-10 p-0 bg-gradient-to-br from-[#9D4EDD] to-[#00D9FF] hover:scale-105 transition-transform disabled:opacity-40"
                  style={{ boxShadow: "0 0 20px rgba(157,78,221,0.4)" }}
                >
                  <Send className="h-4 w-4" />
                </Button>
              </div>
              <p className="text-[10px] text-white/20 mt-1.5 text-center">
                Powered by SentinelNexus AI · Press Enter to send
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
