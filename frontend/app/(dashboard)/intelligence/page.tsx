"use client";

import { useEffect, useState } from "react";
import { 
  BrainCircuit, AlertTriangle, ShieldCheck, 
  Lightbulb, ExternalLink, ShieldAlert,
  Search, Link as LinkIcon
} from "lucide-react";
import Link from "next/link";
import { api } from "@/lib/api";

interface Evidence {
  finding_ids?: string[];
  finding_titles?: string[];
  event_ids?: string[];
  event_titles?: string[];
  affected_asset_count?: number;
}

interface Insight {
  id: string;
  type: "critical" | "recommendation";
  title: string;
  description: string;
  asset_ip?: string;
  evidence: Evidence;
}

export default function CorrelatedIntelligencePage() {
  const [insights, setInsights] = useState<Insight[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchInsights() {
      try {
        const res = await api.get<Insight[]>("/intelligence");
        setInsights(res);
      } catch (error) {
        console.error("Failed to load intelligence:", error);
      } finally {
        setLoading(false);
      }
    }
    fetchInsights();
  }, []);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <BrainCircuit className="h-8 w-8 animate-pulse text-primary" />
          <p className="text-sm text-muted">Correlating evidence...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-ink">Correlated Intelligence</h1>
          <p className="mt-2 text-muted">Evidence-backed correlations and automated insights</p>
        </div>
        {/* "Engine Active" was static markup with no state behind it. This
            reports what the last correlation run actually produced. */}
        <div className="flex items-center gap-2 rounded-lg border border-border bg-surface px-4 py-2 text-muted">
          <ShieldCheck className="h-5 w-5" />
          <span className="text-sm">
            {insights.length} correlation{insights.length === 1 ? "" : "s"} from your data
          </span>
        </div>
      </div>

      {insights.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-surface p-12 text-center shadow-lg">
          <div className="mb-4 rounded-full bg-surface-hover p-6">
            <BrainCircuit className="h-12 w-12 text-muted/30" />
          </div>
          <h3 className="text-lg font-medium text-ink">Nothing to correlate</h3>
          <p className="mt-2 max-w-md text-sm text-muted">
            The engine found no evidence-backed correlations in the data it
            holds. That is not the same as a clean posture — if you have not
            completed a scan, there is nothing here to correlate in the first
            place.
          </p>
        </div>
      ) : (
        <div className="grid gap-6">
          {insights.map((insight) => (
            <div 
              key={insight.id} 
              className={`glossy-card relative overflow-hidden rounded-xl border p-6 shadow-lg transition-all hover:shadow-xl ${
                insight.type === "critical" 
                  ? "border-rose-500/30" 
                  : "border-amber-500/30"
              }`}
            >
              <div 
                className={`absolute -right-12 -top-12 rounded-full p-20 blur-[60px] ${
                  insight.type === "critical" 
                    ? "bg-rose-500/10" 
                    : "bg-amber-500/10"
                }`} 
              />
              
              <div className="relative z-10 flex items-start gap-5">
                <div 
                  className={`flex-shrink-0 rounded-xl p-3 shadow-lg ${
                    insight.type === "critical" 
                      ? "bg-rose-500/20 text-rose-500 shadow-rose-500/20" 
                      : "bg-amber-500/20 text-amber-500 shadow-amber-500/20"
                  }`}
                >
                  {insight.type === "critical" ? <AlertTriangle className="h-6 w-6" /> : <Lightbulb className="h-6 w-6" />}
                </div>
                
                <div className="flex-1 space-y-4">
                  <div>
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-semibold text-ink">{insight.title}</h3>
                      <span 
                        className={`inline-flex rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                          insight.type === "critical" 
                            ? "bg-rose-500/20 text-rose-500" 
                            : "bg-amber-500/20 text-amber-500"
                        }`}
                      >
                        {insight.type}
                      </span>
                    </div>
                    <p className="mt-2 text-sm text-muted max-w-4xl">{insight.description}</p>
                  </div>

                  <div className="rounded-lg border border-border/50 bg-surface/50 p-4">
                    <h4 className="mb-3 flex items-center gap-2 text-sm font-semibold text-ink">
                      <Search className="h-4 w-4 text-primary" />
                      Supporting Evidence
                    </h4>
                    
                    <div className="space-y-4">
                      {insight.asset_ip && (
                        <div className="flex items-center gap-2 text-sm">
                          <span className="text-muted">Target Asset:</span>
                          <span className="font-mono font-medium text-ink">{insight.asset_ip}</span>
                        </div>
                      )}
                      
                      {insight.evidence.affected_asset_count && (
                        <div className="flex items-center gap-2 text-sm">
                          <span className="text-muted">Affected Assets:</span>
                          <span className="font-medium text-ink">{insight.evidence.affected_asset_count} hosts</span>
                        </div>
                      )}

                      {insight.evidence.finding_titles && insight.evidence.finding_titles.length > 0 && (
                        <div className="space-y-2">
                          <p className="text-xs font-semibold uppercase tracking-wider text-muted">Related Findings</p>
                          <ul className="space-y-1.5">
                            {insight.evidence.finding_titles.map((title, i) => (
                              <li key={i} className="flex items-start gap-2 text-sm text-ink/80">
                                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-primary/60" />
                                <span>{title}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {insight.evidence.event_titles && insight.evidence.event_titles.length > 0 && (
                        <div className="space-y-2">
                          <p className="text-xs font-semibold uppercase tracking-wider text-muted">Correlated Events</p>
                          <ul className="space-y-1.5">
                            {insight.evidence.event_titles.map((title, i) => (
                              <li key={i} className="flex items-start gap-2 text-sm text-ink/80">
                                <LinkIcon className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-primary/60" />
                                <span>{title}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="flex-shrink-0">
                  {/* Had no handler. Every insight carries the exact finding
                      ids it was derived from, so "investigate" opens those
                      rather than being a word on a button. */}
                  {insight.evidence.finding_ids?.length ? (
                    <Link
                      href={`/vulnerabilities?finding=${insight.evidence.finding_ids[0]}`}
                      className="flex items-center gap-2 rounded-lg bg-primary/10 px-4 py-2 text-sm font-medium text-primary transition-colors hover:bg-primary/20"
                    >
                      Investigate <ExternalLink className="h-4 w-4" />
                    </Link>
                  ) : insight.asset_ip ? (
                    <Link
                      href={`/assets?search=${encodeURIComponent(insight.asset_ip)}`}
                      className="flex items-center gap-2 rounded-lg bg-primary/10 px-4 py-2 text-sm font-medium text-primary transition-colors hover:bg-primary/20"
                    >
                      Open asset <ExternalLink className="h-4 w-4" />
                    </Link>
                  ) : (
                    <span className="block max-w-[9rem] text-right text-xs text-muted">
                      No record referenced
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
