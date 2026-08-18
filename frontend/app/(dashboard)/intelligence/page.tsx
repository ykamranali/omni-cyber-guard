"use client";

import { useQuery } from "@tanstack/react-query";
import { Topbar } from "@/components/layout/topbar";
import { BrainCircuit, Activity, AlertTriangle, ShieldCheck, Crosshair } from "lucide-react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";

interface Insight {
  id: string;
  type: "critical" | "warning" | "recommendation";
  title: string;
  description: string;
  asset_ip?: string;
  confidence_score: number;
}

export default function IntelligencePage() {
  const { data: insights = [], isLoading } = useQuery({
    queryKey: ["insights"],
    queryFn: () => api.get<Insight[]>("/intelligence/insights")
  });

  const targetedAssets = insights.filter(i => i.asset_ip).map(i => ({ ip: i.asset_ip, risk: i.confidence_score }));

  return (
    <>
      <Topbar title="Security Intelligence" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <div>
          <h1 className="text-2xl font-bold text-ink">Automated Security Intelligence</h1>
          <p className="text-sm text-muted">Heuristic analysis correlating real-time threats with known asset vulnerabilities.</p>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          <div className="circuit-panel p-6 col-span-2">
            <h3 className="font-semibold text-primary neon-text flex items-center gap-2 mb-4 text-lg">
              <BrainCircuit className="text-primary h-6 w-6 animate-pulse-glow" /> Heuristic Insights Engine
            </h3>
            <div className="space-y-4">
              {isLoading ? (
                <div className="text-muted p-8 text-center animate-pulse">Running heuristic correlation engine...</div>
              ) : insights.length === 0 ? (
                <div className="text-muted p-8 text-center">No insights available at this time.</div>
              ) : (
                <div className="relative border-l-2 border-primary/30 pl-8 ml-4 space-y-6">
                  {insights.map((insight) => (
                    <div key={insight.id} className="relative p-4 circuit-panel flex gap-4 hover:border-primary/80 transition-colors bg-surface/90">
                      {/* Circuit trace line connecting to main bus */}
                      <div className="absolute -left-8 top-1/2 w-8 h-[2px] bg-primary/40">
                        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-1 bg-primary rounded-full shadow-neon" />
                      </div>
                      
                      <div className="mt-1 flex-shrink-0 p-2 border border-current shadow-[inset_0_0_10px_currentColor]">
                      {insight.type === "critical" ? <AlertTriangle className="h-6 w-6 text-red-500 animate-pulse-glow" /> :
                       insight.type === "warning" ? <Activity className="h-6 w-6 text-orange-500 animate-pulse-glow" /> :
                       <ShieldCheck className="h-6 w-6 text-blue-500 animate-pulse-glow" />}
                    </div>
                    <div className="flex-1">
                      <div className="flex justify-between items-start">
                        <h4 className="font-semibold text-ink">{insight.title}</h4>
                        <span className="text-xs font-mono text-muted bg-surface border border-border px-2 py-1 rounded">
                          Confidence: {insight.confidence_score}%
                        </span>
                      </div>
                      <p className="text-sm text-ink/80 mt-1">{insight.description}</p>
                      
                      {insight.type === "critical" && (
                         <div className="mt-3 flex gap-2">
                           <Button size="sm" variant="danger" className="h-7 text-xs">Isolate Asset</Button>
                           <Button size="sm" variant="outline" className="h-7 text-xs">Create Incident</Button>
                         </div>
                      )}
                    </div>
                  </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="space-y-6">
            <div className="network-lightning-bg circuit-panel p-6">
              <h3 className="font-semibold text-red-500 neon-text-critical flex items-center gap-2 mb-2 text-lg relative z-10">
                <Crosshair className="text-red-500 h-6 w-6 animate-pulse-glow" /> Top Targeted Assets
              </h3>
              <p className="text-xs text-muted mb-4 uppercase tracking-widest font-bold">Assets with the highest combination of severity and active network probing.</p>
              
              <div className="space-y-3">
                {targetedAssets.length === 0 ? (
                   <div className="text-muted text-sm italic">No actively targeted vulnerable assets detected.</div>
                ) : (
                  targetedAssets.map((asset, i) => (
                    <div key={i} className="flex justify-between items-center text-sm border-b border-border/50 pb-2">
                      <span className="font-mono font-medium">{asset.ip}</span>
                      <span className="text-red-500 font-bold bg-red-500/10 px-2 rounded-full">Risk: {asset.risk}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="network-lightning-bg circuit-panel border-primary shadow-neon p-6 relative overflow-hidden">
               <div className="absolute inset-0 bg-primary/20 h-full w-full animate-satellite-beam opacity-20 pointer-events-none mix-blend-screen" />
               <h3 className="font-bold text-primary neon-text mb-2 text-lg relative z-10">Engine Status</h3>
               <p className="text-sm text-ink/80 relative z-10">The Heuristic Engine is currently running and actively correlating live network events against open asset vulnerabilities.</p>
               <div className="mt-4 flex items-center gap-2 text-xs font-bold text-green-500 bg-green-500/10 px-3 py-1.5 rounded-md w-fit border border-green-500/50 shadow-[0_0_10px_#22C55E] relative z-10 tracking-wider">
                 <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse-glow shadow-[0_0_5px_#22C55E]" />
                 FULLY OPERATIONAL
               </div>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
