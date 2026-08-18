"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Satellite, ShieldAlert, Activity, Search, Shield, AlertTriangle } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import { Topbar } from "@/components/layout/topbar";

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
}

export default function ThreatIntelligencePage() {
  const [search, setSearch] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["threat-intel"],
    queryFn: () => api.get<ThreatIntel>("/threat-intel"),
    refetchInterval: 3000, // Poll every 3 seconds for real-time feel
  });

  if (isLoading && !data) {
    return (
      <>
        <Topbar title="Threat Intelligence" />
        <div className="flex flex-1 items-center justify-center p-6">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
        </div>
      </>
    );
  }

  const filteredAdvisories = data?.latest_advisories.filter((a) =>
    a.title.toLowerCase().includes(search.toLowerCase()) ||
    a.description.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <>
      <Topbar title="Threat Intelligence" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <div>
          <p className="text-sm text-muted">
            Live monitoring of local network traffic. Intercepts and analyzes packets heuristically for reconnaissance, insecure protocols, and basic attacks.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <div className="hud-panel p-5 group">
            <div className="flex items-center gap-4">
              <div className={cn("glossy-icon p-3 rounded-xl border border-current shadow-neon transition-transform group-hover:scale-110", data?.global_risk_level === "ELEVATED" ? "text-red-500" : "text-primary")}>
                <Activity className={cn("h-6 w-6 animate-pulse-glow")} />
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-widest font-bold text-muted">Network Risk Level</p>
                <h2 className={cn("text-3xl font-bold tracking-tight neon-text", data?.global_risk_level === "ELEVATED" ? "text-red-500" : "text-primary")}>
                  {data?.global_risk_level || "UNKNOWN"}
                </h2>
              </div>
            </div>
          </div>
          <div className="hud-panel p-5 group">
            <div className="flex items-center gap-4">
              <div className="glossy-icon p-3 rounded-xl border border-primary text-primary shadow-neon transition-transform group-hover:scale-110">
                <ShieldAlert className="h-6 w-6 animate-pulse-glow" />
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-widest font-bold text-muted">Events Detected (Last 60s)</p>
                <h2 className="text-3xl font-bold tracking-tight neon-text text-primary">{data?.active_campaigns || 0}</h2>
              </div>
            </div>
          </div>
          <div className="hud-panel p-5 group">
            <div className="flex items-center gap-4">
              <div className="glossy-icon p-3 rounded-xl border border-purple-500 text-purple-500 shadow-[0_0_15px_#A855F7] transition-transform group-hover:scale-110">
                <Satellite className="h-6 w-6 animate-spin-slow" />
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-widest font-bold text-muted">Zero-Days Tracked</p>
                <h2 className="text-3xl font-bold tracking-tight neon-text text-purple-500">{data?.zero_days_tracked || 0}</h2>
              </div>
            </div>
          </div>
        </div>

        <div className="satellite-feed-bg rounded-sm relative overflow-hidden">
          {/* Flowing energy wave */}
          <div className="absolute inset-0 top-1/2 -translate-y-1/2 h-32 w-[200vw] bg-[radial-gradient(ellipse_at_center,rgba(14,165,233,0.4)_0%,transparent_50%)] animate-energy-wave mix-blend-screen pointer-events-none z-0" />
          {/* Floating red threat particles */}
          <div className="absolute top-10 left-10 text-red-500 animate-float-particle opacity-50 z-10"><AlertTriangle size={16} /></div>
          <div className="absolute top-32 right-20 text-red-500 animate-float-particle opacity-40 z-10" style={{animationDelay: "1s"}}><AlertTriangle size={24} /></div>
          <div className="absolute bottom-10 left-1/3 text-orange-500 animate-float-particle opacity-60 z-10" style={{animationDelay: "2s"}}><AlertTriangle size={12} /></div>
          
          <div className="absolute inset-0 bg-primary h-2 w-full animate-satellite-beam opacity-80 shadow-[0_0_20px_#0EA5E9,0_0_40px_#0EA5E9] pointer-events-none z-20 mix-blend-screen" />
          <div className="border-b border-primary/40 bg-surface/80 backdrop-blur p-4 relative z-10">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-ink neon-text">Real-Time Threat Feed</h2>
                <div className="flex items-center gap-1.5 text-xs text-primary animate-pulse ml-2 border border-primary shadow-neon bg-primary/10 px-2 py-0.5 rounded-full uppercase tracking-wider font-bold">
                  <span className="h-2 w-2 rounded-full bg-primary shadow-neon" /> LIVE
                </div>
              </div>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <input
                  type="text"
                  placeholder="Search events..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-64 rounded-lg border border-border bg-surface-hover pl-9 pr-4 py-2 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>
          </div>
          <div className="divide-y divide-primary/10 relative z-10">
            {filteredAdvisories?.map((advisory) => (
              <div key={advisory.id} className="flex gap-4 p-5 hover:bg-primary/5 transition-colors group">
                <div className="mt-1 flex-shrink-0">
                  {advisory.severity === "CRITICAL" ? (
                    <AlertTriangle className="h-6 w-6 text-red-500" />
                  ) : advisory.severity === "HIGH" ? (
                    <AlertTriangle className="h-6 w-6 text-orange-500" />
                  ) : (
                    <Shield className="h-6 w-6 text-blue-500" />
                  )}
                </div>
                <div className="flex-1 space-y-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-semibold text-ink">{advisory.title}</h3>
                      <div className="mt-1 flex items-center gap-3 text-xs text-muted">
                        <span className="font-mono text-primary">{advisory.id}</span>
                        <span>•</span>
                        <span>{formatDistanceToNow(new Date(advisory.timestamp), { addSuffix: true })}</span>
                      </div>
                    </div>
                    <div className="text-right">
                      <span className={cn(
                        "inline-flex rounded-full px-2 py-0.5 text-xs font-semibold",
                        advisory.severity === "CRITICAL" ? "bg-red-500/10 text-red-500" :
                        advisory.severity === "HIGH" ? "bg-orange-500/10 text-orange-500" :
                        advisory.severity === "MEDIUM" ? "bg-yellow-500/10 text-yellow-500" :
                        "bg-blue-500/10 text-blue-500"
                      )}>
                        {advisory.severity}
                      </span>
                    </div>
                  </div>
                  <p className="text-sm text-ink/80">{advisory.description}</p>
                  <div className="flex gap-2 pt-1">
                    {advisory.tags.map((tag) => (
                      <span key={tag} className="rounded border border-border bg-surface-hover px-2 py-0.5 text-[10px] font-medium text-muted">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
            {filteredAdvisories?.length === 0 && (
              <div className="p-8 text-center text-muted">Monitoring local network traffic. No anomalies detected yet.</div>
            )}
          </div>
        </div>
      </main>
    </>
  );
}
