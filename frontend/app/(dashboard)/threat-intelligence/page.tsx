"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Satellite, ShieldAlert, Activity, Search, Shield, AlertTriangle } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import { motion, AnimatePresence } from "framer-motion";

interface ThreatEvent {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  timestamp: string;
  tags: string[];
}

interface ThreatIntel {
  global_risk_level: string;
  active_campaigns: number;
  zero_days_tracked: number;
  latest_advisories: ThreatEvent[];
  global_cves?: ThreatEvent[];
}

export default function ThreatIntelligencePage() {
  const [search, setSearch] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["threat-intel"],
    queryFn: () => api.get<ThreatIntel>("/threat-intel"),
    refetchInterval: 3000,
  });

  const filteredAdvisories = data?.latest_advisories.filter((a) =>
    a.title.toLowerCase().includes(search.toLowerCase()) ||
    a.description.toLowerCase().includes(search.toLowerCase())
  );

  const container = {
    hidden: { opacity: 0 },
    show: { opacity: 1, transition: { staggerChildren: 0.1 } }
  };

  const item = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <div className="flex flex-col gap-8 p-8 max-w-[1600px] mx-auto w-full">
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/50 pb-6"
      >
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 border border-primary/20 shadow-neon">
            <Satellite className="h-6 w-6 text-primary animate-pulse-glow" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-ink neon-text">Global Threat Intelligence</h1>
            <p className="text-muted mt-1">Live heuristic monitoring and external CVE advisories.</p>
          </div>
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Filter intel feed..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full sm:w-64 rounded-xl border border-border/50 bg-surface/50 pl-10 pr-4 py-2.5 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/50 transition-all shadow-[inset_0_2px_4px_rgba(0,0,0,0.1)]"
          />
        </div>
      </motion.div>

      {isLoading && !data ? (
        <div className="flex h-64 items-center justify-center">
          <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary border-t-transparent shadow-neon" />
        </div>
      ) : (
        <motion.div variants={container} initial="hidden" animate="show" className="grid gap-8">
          
          {/* Top KPI Cards */}
          <div className="grid gap-6 md:grid-cols-3">
            <motion.div variants={item} className="jarvis-panel p-6 group cursor-default">
              <div className="flex items-center gap-4 relative z-10">
                <div className={cn("flex h-14 w-14 shrink-0 items-center justify-center rounded-xl border shadow-glass transition-transform group-hover:scale-110", data?.global_risk_level === "ELEVATED" ? "bg-red-500/10 border-red-500/50 text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.4)]" : "bg-primary/10 border-primary/50 text-primary shadow-neon")}>
                  <Activity className="h-7 w-7 animate-pulse-glow" />
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-widest font-bold text-muted mb-1">Network Risk Level</p>
                  <h2 className={cn("text-3xl font-bold tracking-tight font-mono", data?.global_risk_level === "ELEVATED" ? "text-red-500 neon-text-critical" : "text-primary neon-text")}>
                    {data?.global_risk_level || "UNKNOWN"}
                  </h2>
                </div>
              </div>
            </motion.div>

            <motion.div variants={item} className="glass-panel p-6 group cursor-default border-primary/30">
              <div className="flex items-center gap-4 relative z-10">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl bg-orange-500/10 border border-orange-500/50 text-orange-500 shadow-[0_0_15px_rgba(249,115,22,0.4)] transition-transform group-hover:scale-110">
                  <ShieldAlert className="h-7 w-7 animate-pulse-glow" />
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-widest font-bold text-muted mb-1">Active Campaigns</p>
                  <h2 className="text-3xl font-bold tracking-tight font-mono text-orange-500 neon-text">{data?.active_campaigns || 0}</h2>
                </div>
              </div>
            </motion.div>

            <motion.div variants={item} className="glass-panel p-6 group cursor-default border-purple-500/30">
              <div className="flex items-center gap-4 relative z-10">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl bg-purple-500/10 border border-purple-500/50 text-purple-500 shadow-[0_0_15px_rgba(168,85,247,0.4)] transition-transform group-hover:scale-110">
                  <Satellite className="h-7 w-7 animate-spin-slow" />
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-widest font-bold text-muted mb-1">Zero-Days Tracked</p>
                  <h2 className="text-3xl font-bold tracking-tight font-mono text-purple-500 neon-text">{data?.zero_days_tracked || 0}</h2>
                </div>
              </div>
            </motion.div>
          </div>

          <div className="grid gap-8 xl:grid-cols-2">
            {/* Live Feed */}
            <motion.div variants={item} className="satellite-feed-bg rounded-2xl relative overflow-hidden h-[600px] flex flex-col shadow-glass border-primary/50">
              <div className="absolute inset-0 top-1/2 -translate-y-1/2 h-32 w-[200vw] bg-[radial-gradient(ellipse_at_center,rgba(14,165,233,0.4)_0%,transparent_50%)] animate-energy-wave mix-blend-screen pointer-events-none z-0" />
              <div className="absolute top-10 left-10 text-red-500 animate-float-particle opacity-50 z-10"><AlertTriangle size={16} /></div>
              <div className="absolute top-32 right-20 text-red-500 animate-float-particle opacity-40 z-10" style={{animationDelay: "1s"}}><AlertTriangle size={24} /></div>
              
              <div className="absolute inset-0 bg-primary h-2 w-full animate-satellite-beam opacity-80 shadow-[0_0_20px_#0EA5E9,0_0_40px_#0EA5E9] pointer-events-none z-20 mix-blend-screen" />
              
              <div className="border-b border-primary/40 bg-surface/80 backdrop-blur-md p-5 relative z-30">
                <div className="flex items-center gap-3">
                  <h2 className="text-lg font-bold text-ink neon-text tracking-wide">Live Intercept Feed</h2>
                  <div className="flex items-center gap-2 text-[10px] text-primary animate-pulse border border-primary shadow-neon bg-primary/10 px-2 py-1 rounded-full uppercase tracking-widest font-bold">
                    <span className="h-2 w-2 rounded-full bg-primary shadow-neon" /> LINK ACTIVE
                  </div>
                </div>
              </div>
              
              <div className="flex-1 overflow-y-auto p-4 space-y-4 relative z-30 scrollbar-thin scrollbar-thumb-primary/50 scrollbar-track-transparent">
                <AnimatePresence>
                  {filteredAdvisories?.map((advisory) => (
                    <motion.div 
                      key={advisory.id} 
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, scale: 0.95 }}
                      className="flex gap-4 p-5 rounded-xl bg-surface/80 backdrop-blur-sm border border-primary/20 hover:border-primary/50 hover:bg-primary/5 transition-colors group shadow-[0_4px_15px_rgba(0,0,0,0.1)]"
                    >
                      <div className="mt-1 flex-shrink-0">
                        {advisory.severity === "CRITICAL" ? (
                          <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 shadow-[0_0_10px_rgba(239,68,68,0.2)]">
                            <AlertTriangle className="h-5 w-5" />
                          </div>
                        ) : advisory.severity === "HIGH" ? (
                          <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/30 text-orange-500 shadow-[0_0_10px_rgba(249,115,22,0.2)]">
                            <AlertTriangle className="h-5 w-5" />
                          </div>
                        ) : (
                          <div className="p-2 rounded-lg bg-primary/10 border border-primary/30 text-primary shadow-[0_0_10px_rgba(14,165,233,0.2)]">
                            <Shield className="h-5 w-5" />
                          </div>
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-4 mb-2">
                          <h3 className="font-bold text-ink truncate text-base">{advisory.title}</h3>
                          <span className={cn(
                            "inline-flex shrink-0 rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                            advisory.severity === "CRITICAL" ? "bg-red-500/10 text-red-500 border border-red-500/20" :
                            advisory.severity === "HIGH" ? "bg-orange-500/10 text-orange-500 border border-orange-500/20" :
                            advisory.severity === "MEDIUM" ? "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20" :
                            "bg-primary/10 text-primary border border-primary/20"
                          )}>
                            {advisory.severity}
                          </span>
                        </div>
                        <p className="text-sm text-muted leading-relaxed line-clamp-2 mb-3">{advisory.description}</p>
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap gap-2">
                            {advisory.tags.map((tag) => (
                              <span key={tag} className="rounded bg-surface-hover/80 border border-border/50 px-2 py-0.5 text-[10px] font-semibold text-muted uppercase tracking-wider">
                                {tag}
                              </span>
                            ))}
                          </div>
                          <div className="flex items-center gap-2 text-[10px] font-mono text-muted">
                            <span className="text-primary/70">{advisory.id}</span>
                            <span>•</span>
                            <span>{formatDistanceToNow(new Date(advisory.timestamp), { addSuffix: true })}</span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
                {filteredAdvisories?.length === 0 && (
                  <div className="p-12 text-center flex flex-col items-center justify-center opacity-50">
                    <Shield className="h-12 w-12 text-primary mb-4" />
                    <p className="text-primary font-mono text-sm">Monitoring local network traffic.</p>
                    <p className="text-muted text-xs mt-1">No anomalous signatures detected in current packet stream.</p>
                  </div>
                )}
              </div>
            </motion.div>

            {/* Global CVEs */}
            {data?.global_cves && (
              <motion.div variants={item} className="rounded-2xl glass-panel overflow-hidden h-[600px] flex flex-col border-purple-500/30">
                <div className="border-b border-border/50 bg-surface/50 p-5">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-lg font-bold text-ink flex items-center gap-2"><Satellite size={18} className="text-purple-500 animate-pulse" /> Global Vulnerability Database</h2>
                      <p className="text-xs text-muted mt-1 tracking-wide">Latest critical CVEs tracked by Omni Intel Division.</p>
                    </div>
                  </div>
                </div>
                
                <div className="flex-1 overflow-y-auto p-2 scrollbar-thin scrollbar-thumb-border scrollbar-track-transparent">
                  {data.global_cves.map((cve, i) => (
                    <motion.div 
                      key={cve.id} 
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.1 }}
                      className="p-5 flex gap-4 hover:bg-surface-hover/50 transition-colors border-b border-border/30 last:border-0 group cursor-pointer"
                    >
                      <div className="mt-1 flex-shrink-0">
                        <ShieldAlert size={20} className={cn(
                          "transition-transform group-hover:scale-110",
                          cve.severity === "CRITICAL" ? "text-red-500 drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]" : 
                          cve.severity === "HIGH" ? "text-orange-500" : "text-yellow-500"
                        )} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-4 mb-1">
                          <h3 className="font-semibold text-ink text-sm truncate">{cve.title}</h3>
                          <span className={cn(
                            "inline-flex shrink-0 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                            cve.severity === "CRITICAL" ? "bg-red-500/10 text-red-500" :
                            cve.severity === "HIGH" ? "bg-orange-500/10 text-orange-500" : "bg-yellow-500/10 text-yellow-500"
                          )}>{cve.severity}</span>
                        </div>
                        <p className="text-xs text-muted leading-relaxed line-clamp-2 mb-2">{cve.description}</p>
                        <div className="flex items-center justify-between">
                          <p className="text-[10px] text-muted font-mono bg-surface-hover px-1.5 py-0.5 rounded inline-block">
                            {cve.id}
                          </p>
                          <span className="text-[10px] text-muted">
                            {formatDistanceToNow(new Date((cve as any).published_at || cve.timestamp), { addSuffix: true })}
                          </span>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </motion.div>
            )}
          </div>
        </motion.div>
      )}
    </div>
  );
}
