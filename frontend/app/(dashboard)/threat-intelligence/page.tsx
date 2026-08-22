"use client";

import { useEffect, useState } from "react";
import { 
  Satellite, AlertTriangle, ShieldAlert, Activity, 
  Database, RefreshCw, Zap, ExternalLink 
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api";

interface ThreatEntry {
  id: string;
  title: string;
  description: string;
  severity: string;
  cvss: number | null;
  epss: number | null;
  known_exploited: boolean;
  timestamp: string | null;
  tags: string[];
}

interface ThreatIntelResponse {
  configured: boolean;
  sources: string[];
  last_synced_at: string | null;
  total_records: number;
  entries: ThreatEntry[];
  message: string;
}

export default function ThreatIntelligencePage() {
  const [data, setData] = useState<ThreatIntelResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchIntel() {
      try {
        const res = await api.get<ThreatIntelResponse>("/threat-intel");
        setData(res);
      } catch (error) {
        console.error("Failed to load threat intel:", error);
      } finally {
        setLoading(false);
      }
    }
    fetchIntel();
  }, []);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
          <p className="text-sm text-muted">Loading Threat Intelligence...</p>
        </div>
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-ink">Threat Intelligence</h1>
          <p className="mt-2 text-muted">Real-time global vulnerability & exploit tracking</p>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-4">
        <div className="glossy-card relative overflow-hidden rounded-xl border border-border p-6 shadow-lg">
          <div className="absolute -right-6 -top-6 rounded-full bg-primary/10 p-10 blur-3xl" />
          <div className="flex items-center gap-4">
            <div className="rounded-xl bg-primary/20 p-3 text-primary shadow-[0_0_15px_rgba(var(--color-primary)/0.3)]">
              <Database className="h-6 w-6" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted">Total Tracked CVEs</p>
              <h3 className="text-2xl font-bold text-ink">{data.total_records.toLocaleString()}</h3>
            </div>
          </div>
        </div>

        <div className="glossy-card relative overflow-hidden rounded-xl border border-border p-6 shadow-lg">
          <div className="absolute -right-6 -top-6 rounded-full bg-emerald-500/10 p-10 blur-3xl" />
          <div className="flex items-center gap-4">
            <div className="rounded-xl bg-emerald-500/20 p-3 text-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.3)]">
              <Activity className="h-6 w-6" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted">Data Sources</p>
              <h3 className="text-2xl font-bold text-ink">{data.sources.length}</h3>
            </div>
          </div>
        </div>

        <div className="glossy-card relative overflow-hidden rounded-xl border border-border p-6 shadow-lg">
          <div className="absolute -right-6 -top-6 rounded-full bg-amber-500/10 p-10 blur-3xl" />
          <div className="flex items-center gap-4">
            <div className="rounded-xl bg-amber-500/20 p-3 text-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.3)]">
              <Zap className="h-6 w-6" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted">Recent Criticals</p>
              <h3 className="text-2xl font-bold text-ink">
                {data.entries.filter((e) => e.severity === "CRITICAL").length}
              </h3>
            </div>
          </div>
        </div>

        <div className="glossy-card relative overflow-hidden rounded-xl border border-border p-6 shadow-lg">
          <div className="absolute -right-6 -top-6 rounded-full bg-rose-500/10 p-10 blur-3xl" />
          <div className="flex items-center gap-4">
            <div className="rounded-xl bg-rose-500/20 p-3 text-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.3)]">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted">CISA KEV Matches</p>
              <h3 className="text-2xl font-bold text-ink">
                {data.entries.filter((e) => e.known_exploited).length}
              </h3>
            </div>
          </div>
        </div>
      </div>

      {!data.configured && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-6">
          <div className="flex gap-4">
            <AlertTriangle className="h-6 w-6 text-amber-500" />
            <div>
              <h3 className="font-semibold text-amber-500">Feed Synchronization Required</h3>
              <p className="mt-1 text-sm text-muted">{data.message}</p>
            </div>
          </div>
        </div>
      )}

      {data.configured && (
        <div className="rounded-xl border border-border bg-surface p-6 shadow-lg backdrop-blur-xl">
          <div className="mb-6 flex items-center justify-between">
            <h2 className="text-lg font-bold text-ink">Recent Intelligence Observations</h2>
            <div className="flex items-center gap-2 text-sm text-muted">
              <RefreshCw className="h-4 w-4" />
              <span>
                Last synced:{" "}
                {data.last_synced_at
                  ? formatDistanceToNow(new Date(data.last_synced_at), { addSuffix: true })
                  : "Never"}
              </span>
            </div>
          </div>

          {data.entries.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Satellite className="mb-4 h-12 w-12 text-muted/30" />
              <p className="text-lg font-medium text-ink">No observations recorded</p>
              <p className="mt-1 text-sm text-muted">
                The global intelligence feed is currently empty.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {data.entries.map((entry) => (
                <div key={entry.id} className="py-5 transition-colors hover:bg-surface-hover/50">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-3">
                        <h3 className="text-base font-semibold text-primary">{entry.title}</h3>
                        {entry.known_exploited && (
                          <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rose-500">
                            <ShieldAlert className="h-3 w-3" /> CISA KEV
                          </span>
                        )}
                        {entry.severity === "CRITICAL" && (
                          <span className="inline-flex rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rose-500">
                            Critical
                          </span>
                        )}
                        {entry.severity === "HIGH" && (
                          <span className="inline-flex rounded-full bg-amber-500/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-500">
                            High
                          </span>
                        )}
                      </div>
                      <p className="mt-2 text-sm text-muted line-clamp-2 max-w-4xl">{entry.description}</p>
                      
                      <div className="mt-4 flex flex-wrap gap-3 text-xs">
                        {entry.cvss !== null && (
                          <div className="flex items-center gap-1.5 rounded-md border border-border bg-surface-hover px-2 py-1">
                            <span className="text-muted">CVSS:</span>
                            <span className="font-mono font-bold text-ink">{entry.cvss.toFixed(1)}</span>
                          </div>
                        )}
                        {entry.epss !== null && (
                          <div className="flex items-center gap-1.5 rounded-md border border-border bg-surface-hover px-2 py-1">
                            <span className="text-muted">EPSS:</span>
                            <span className="font-mono font-bold text-ink">{(entry.epss * 100).toFixed(2)}%</span>
                          </div>
                        )}
                        {entry.tags.map(tag => (
                          <div key={tag} className="flex items-center gap-1.5 rounded-md border border-border bg-surface-hover px-2 py-1">
                            <span className="text-muted">#</span>
                            <span className="font-mono text-ink">{tag}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-muted">
                        {entry.timestamp ? formatDistanceToNow(new Date(entry.timestamp), { addSuffix: true }) : "Unknown time"}
                      </p>
                      <button className="mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-primary hover:text-primary/80">
                        View Details <ExternalLink className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
