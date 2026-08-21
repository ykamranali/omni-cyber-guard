"use client";

import { useQuery } from "@tanstack/react-query";
import { Topbar } from "@/components/layout/topbar";
import { Activity, AlertTriangle, BrainCircuit, Crosshair, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface InsightEvidence {
  finding_ids?: string[];
  finding_titles?: string[];
  event_ids?: string[];
  event_titles?: string[];
  affected_asset_count?: number;
}

interface Insight {
  id: string;
  type: "critical" | "warning" | "recommendation";
  title: string;
  description: string;
  asset_ip?: string;
  evidence: InsightEvidence;
}

/**
 * Correlated intelligence.
 *
 * Every insight below names the findings and observed events it was derived
 * from. The previous version displayed an invented "Confidence: 98%" badge on
 * each card and always rendered a reassuring "Posture is Optimal" entry when
 * nothing correlated — neither number nor conclusion was computed from data.
 */
export default function IntelligencePage() {
  const { data: insights = [], isLoading } = useQuery({
    queryKey: ["insights"],
    queryFn: () => api.get<Insight[]>("/intelligence/insights"),
  });

  const correlatedAssets = insights
    .filter((insight) => insight.asset_ip)
    .map((insight) => ({
      ip: insight.asset_ip as string,
      findings: insight.evidence?.finding_ids?.length ?? 0,
      events: insight.evidence?.event_ids?.length ?? 0,
    }));

  return (
    <>
      <Topbar title="Security Intelligence" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <div>
          <h1 className="text-2xl font-bold text-ink">Correlated Intelligence</h1>
          <p className="text-sm text-muted">
            Correlations between open findings and events observed by the passive monitor. Each
            insight lists the records it was derived from.
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          <div className="circuit-panel col-span-full p-6 md:col-span-2">
            <h3 className="mb-4 flex items-center gap-2 text-lg font-semibold text-primary neon-text">
              <BrainCircuit className="h-6 w-6 animate-pulse-glow text-primary" /> Correlation engine
            </h3>

            {isLoading ? (
              <div className="animate-pulse p-8 text-center text-muted">Correlating findings with observed events…</div>
            ) : insights.length === 0 ? (
              <div className="space-y-2 p-8 text-center">
                <ShieldCheck className="mx-auto h-10 w-10 text-muted/50" />
                <p className="text-sm text-ink/80">No correlations found</p>
                <p className="mx-auto max-w-md text-xs leading-relaxed text-muted">
                  Nothing in the current findings matched anything the passive monitor observed.
                  This is not an assessment of your security posture — it means there was nothing
                  to correlate.
                </p>
              </div>
            ) : (
              <div className="relative ml-4 space-y-6 border-l-2 border-primary/30 pl-8">
                {insights.map((insight) => (
                  <div
                    key={insight.id}
                    className="circuit-panel relative flex gap-4 bg-surface/90 p-4 transition-colors hover:border-primary/80"
                  >
                    <div className="absolute -left-8 top-1/2 h-[2px] w-8 bg-primary/40">
                      <div className="absolute left-0 top-1/2 h-1 w-1 -translate-y-1/2 rounded-full bg-primary shadow-neon" />
                    </div>

                    <div className="mt-1 flex-shrink-0 border border-current p-2 shadow-[inset_0_0_10px_currentColor]">
                      {insight.type === "critical" ? (
                        <AlertTriangle className="h-6 w-6 animate-pulse-glow text-red-500" />
                      ) : insight.type === "warning" ? (
                        <Activity className="h-6 w-6 animate-pulse-glow text-orange-500" />
                      ) : (
                        <ShieldCheck className="h-6 w-6 animate-pulse-glow text-blue-500" />
                      )}
                    </div>

                    <div className="min-w-0 flex-1">
                      <h4 className="font-semibold text-ink">{insight.title}</h4>
                      <p className="mt-1 text-sm text-ink/80">{insight.description}</p>

                      <div className="mt-3 rounded-lg border border-border/60 bg-surface p-3">
                        <p className="mb-2 text-[10px] font-bold uppercase tracking-widest text-muted">Evidence</p>
                        <ul className="space-y-1 text-xs text-muted">
                          {insight.evidence?.finding_titles?.map((title, i) => (
                            <li key={`f-${i}`} className="truncate">
                              <span className="font-mono text-primary/70">finding</span> {title}
                            </li>
                          ))}
                          {insight.evidence?.event_titles?.map((title, i) => (
                            <li key={`e-${i}`} className="truncate">
                              <span className="font-mono text-orange-400/80">event</span> {title}
                            </li>
                          ))}
                          {insight.evidence?.affected_asset_count !== undefined && (
                            <li>
                              <span className="font-mono text-primary/70">assets affected</span>{" "}
                              {insight.evidence.affected_asset_count}
                            </li>
                          )}
                        </ul>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-6">
            <div className="network-lightning-bg circuit-panel p-6">
              <h3 className="relative z-10 mb-2 flex items-center gap-2 text-lg font-semibold text-red-500 neon-text-critical">
                <Crosshair className="h-6 w-6 animate-pulse-glow text-red-500" /> Correlated assets
              </h3>
              <p className="mb-4 text-xs font-bold uppercase tracking-widest text-muted">
                Assets with open severe findings that also appear in observed network activity.
              </p>

              <div className="space-y-3">
                {correlatedAssets.length === 0 ? (
                  <div className="text-sm italic text-muted">No assets matched both criteria.</div>
                ) : (
                  correlatedAssets.map((asset) => (
                    <div key={asset.ip} className="flex items-center justify-between border-b border-border/50 pb-2 text-sm">
                      <span className="font-mono font-medium">{asset.ip}</span>
                      <span className={cn("rounded-full bg-red-500/10 px-2 font-bold text-red-500")}>
                        {asset.findings} finding{asset.findings === 1 ? "" : "s"} · {asset.events} event
                        {asset.events === 1 ? "" : "s"}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
