"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import {
  Activity, AlertTriangle, ChevronRight, Flame, Globe, HelpCircle, Info,
  RefreshCw, Server,
} from "lucide-react";
import { Topbar } from "@/components/layout/topbar";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Overview {
  assessed: boolean;
  exposure_score: number | null;
  assets_total: number;
  assets_assessed: number;
  critical_findings: number;
  known_exploited_findings: number;
  vulnerability_findings: number;
  exposure_findings: number;
  internet_exposed_assets: number;
  assets_without_criticality: number;
  note: string | null;
}

interface Contributor {
  key: string;
  label: string;
  points: number;
  evidence: string;
}

interface UnavailableFactor {
  key: string;
  label: string;
  reason: string;
  max_points: number;
}

interface TopAsset {
  id: string;
  hostname: string;
  ip_address: string | null;
  asset_type: string;
  criticality: string;
  is_internet_facing: boolean;
  exposure_score: number;
  band: string;
  top_contributor: Contributor | null;
}

interface AssetExposure {
  asset_id: string;
  hostname: string;
  ip_address: string | null;
  score: number;
  band: string;
  assessed: boolean;
  note: string;
  contributors: Contributor[];
  unavailable_factors: UnavailableFactor[];
  computed_at: string | null;
}

interface TrendPoint {
  date: string;
  exposure_score: number | null;
  open_findings: number;
  critical_findings: number;
  known_exploited_findings: number;
}

const BAND_STYLES: Record<string, string> = {
  extreme: "text-critical",
  critical: "text-critical",
  high: "text-orange-500",
  medium: "text-yellow-500",
  low: "text-blue-400",
  none: "text-muted",
};

export default function ExposurePage() {
  const queryClient = useQueryClient();
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  const { data: overview } = useQuery({
    queryKey: ["exposure-overview"],
    queryFn: () => api.get<Overview>("/exposure/overview"),
  });

  const { data: topAssets = [] } = useQuery({
    queryKey: ["exposure-top-assets"],
    queryFn: () => api.get<TopAsset[]>("/exposure/top-assets?limit=10"),
  });

  const { data: trend } = useQuery({
    queryKey: ["exposure-trend"],
    queryFn: () => api.get<{ points: TrendPoint[]; note: string | null }>("/exposure/trend?days=30"),
  });

  const { data: detail } = useQuery({
    queryKey: ["exposure-asset", selectedAssetId],
    queryFn: () => api.get<AssetExposure>(`/exposure/assets/${selectedAssetId}`),
    enabled: !!selectedAssetId,
  });

  const recompute = useMutation({
    mutationFn: () => api.post("/exposure/recompute"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exposure-overview"] });
      queryClient.invalidateQueries({ queryKey: ["exposure-top-assets"] });
      queryClient.invalidateQueries({ queryKey: ["exposure-trend"] });
    },
  });

  const score = overview?.exposure_score;

  return (
    <>
      <Topbar title="Exposure Overview" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-ink">Exposure Overview</h1>
            <p className="text-sm text-muted">
              Every score here can be opened to see the contributors that produced it.
            </p>
          </div>
          <Button variant="outline" onClick={() => recompute.mutate()} disabled={recompute.isPending}>
            <RefreshCw className={cn("mr-2 h-4 w-4", recompute.isPending && "animate-spin")} />
            {recompute.isPending ? "Recomputing…" : "Recompute now"}
          </Button>
        </div>

        {overview && !overview.assessed && (
          <div className="flex gap-3 rounded-xl border border-orange-500/30 bg-orange-500/5 p-4">
            <Info className="mt-0.5 h-5 w-5 shrink-0 text-orange-500" />
            <div>
              <p className="text-sm font-semibold text-ink">Nothing has been assessed yet</p>
              <p className="mt-1 text-sm leading-relaxed text-muted">{overview.note}</p>
            </div>
          </div>
        )}

        {/* Headline */}
        <div className="grid gap-4 lg:grid-cols-4">
          <div className="jarvis-panel p-6 lg:col-span-1">
            <p className="text-[10px] font-bold uppercase tracking-widest text-muted">
              Exposure score
            </p>
            <p className={cn(
              "mt-2 font-mono text-5xl font-bold",
              score == null ? "text-muted" : BAND_STYLES[bandOf(score)]
            )}>
              {score == null ? "—" : score.toFixed(0)}
            </p>
            <p className="mt-1 text-xs text-muted">
              {score == null
                ? "Not enough data to score"
                : `Mean across ${overview?.assets_assessed} assessed asset${overview?.assets_assessed === 1 ? "" : "s"}`}
            </p>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:col-span-3 lg:grid-cols-4">
            <Stat
              icon={<AlertTriangle className="h-4 w-4" />}
              label="Critical findings"
              value={overview?.critical_findings}
              tone="critical"
            />
            <Stat
              icon={<Flame className="h-4 w-4" />}
              label="Known exploited"
              value={overview?.known_exploited_findings}
              tone="critical"
              hint="Findings referencing a CVE in the CISA KEV catalogue — exploitation observed in the wild."
            />
            <Stat
              icon={<Globe className="h-4 w-4" />}
              label="Internet facing"
              value={overview?.internet_exposed_assets}
              tone="warn"
              hint="Assets in a network an operator declared internet facing. Never inferred from an address."
            />
            <Stat
              icon={<Server className="h-4 w-4" />}
              label="Assets assessed"
              value={overview ? `${overview.assets_assessed} / ${overview.assets_total}` : undefined}
              tone="neutral"
            />
          </div>
        </div>

        {overview && overview.assets_without_criticality > 0 && overview.assets_total > 0 && (
          <div className="flex gap-3 rounded-xl border border-border bg-surface p-4">
            <HelpCircle className="mt-0.5 h-5 w-5 shrink-0 text-muted" />
            <p className="text-sm leading-relaxed text-muted">
              <span className="font-medium text-ink">
                {overview.assets_without_criticality} of {overview.assets_total} assets have no
                business criticality assigned.
              </span>{" "}
              Criticality is a weighted contributor, so those assets are being scored on technical
              signal alone. Set it from an asset&rsquo;s detail panel.
            </p>
          </div>
        )}

        {/* Trend */}
        <div className="rounded-2xl border border-border bg-surface p-6">
          <div className="mb-4 flex items-center gap-2">
            <Activity className="h-5 w-5 text-primary" />
            <h2 className="text-lg font-semibold text-ink">Exposure trend</h2>
            <span className="text-xs text-muted">last 30 days</span>
          </div>

          {!trend?.points.length ? (
            <div className="flex h-56 flex-col items-center justify-center gap-2 text-center">
              <p className="text-sm text-ink/80">No history recorded yet</p>
              <p className="max-w-md text-xs leading-relaxed text-muted">
                {trend?.note ??
                  "A snapshot is captured once a day. Days the platform was not running are absent from this chart rather than filled in."}
              </p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={224}>
              <AreaChart data={trend.points} margin={{ left: -20, right: 10, top: 10 }}>
                <defs>
                  <linearGradient id="exposureFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#EF4444" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" vertical={false} />
                <XAxis dataKey="date" tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{ background: "#111827", border: "1px solid #1F2937", borderRadius: 8, fontSize: 12 }}
                />
                <Area
                  type="monotone"
                  dataKey="exposure_score"
                  stroke="#EF4444"
                  strokeWidth={2}
                  fill="url(#exposureFill)"
                  name="Exposure score"
                  // A day with no score is a gap, not a zero.
                  connectNulls={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Most exposed assets */}
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="overflow-hidden rounded-2xl border border-border bg-surface">
            <div className="border-b border-border p-4">
              <h2 className="text-lg font-semibold text-ink">Most exposed assets</h2>
              <p className="text-xs text-muted">Select one to see why it scores what it does.</p>
            </div>

            {topAssets.length === 0 ? (
              <p className="p-8 text-center text-sm text-muted">
                No asset has an exposure score yet.
              </p>
            ) : (
              <div className="divide-y divide-border">
                {topAssets.map((asset) => (
                  <button
                    key={asset.id}
                    onClick={() => setSelectedAssetId(asset.id)}
                    className={cn(
                      "flex w-full items-center gap-4 p-4 text-left transition-colors hover:bg-surface-hover/50",
                      selectedAssetId === asset.id && "bg-primary/5"
                    )}
                  >
                    <span className={cn(
                      "w-12 shrink-0 font-mono text-2xl font-bold",
                      BAND_STYLES[asset.band] ?? "text-muted"
                    )}>
                      {asset.exposure_score.toFixed(0)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-ink">{asset.hostname}</p>
                      <p className="truncate text-xs text-muted">
                        {asset.ip_address} · {asset.asset_type.replace(/_/g, " ")}
                        {asset.is_internet_facing && " · internet facing"}
                      </p>
                      {asset.top_contributor && (
                        <p className="mt-0.5 truncate text-[11px] text-muted/80">
                          Largest factor: {asset.top_contributor.label}
                        </p>
                      )}
                    </div>
                    <ChevronRight className="h-4 w-4 shrink-0 text-muted" />
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Why this score */}
          <div className="rounded-2xl border border-border bg-surface p-6">
            <h2 className="text-lg font-semibold text-ink">Why this score?</h2>

            {!detail ? (
              <p className="mt-8 text-center text-sm text-muted">
                Select an asset to see its breakdown.
              </p>
            ) : (
              <>
                <div className="mt-3 flex items-baseline gap-3">
                  <span className={cn("font-mono text-4xl font-bold", BAND_STYLES[detail.band])}>
                    {detail.score.toFixed(0)}
                  </span>
                  <div>
                    <p className="text-sm font-medium text-ink">{detail.hostname}</p>
                    <p className="text-xs uppercase tracking-wider text-muted">{detail.band}</p>
                  </div>
                </div>

                {!detail.assessed && (
                  <p className="mt-3 rounded-lg border border-border bg-surface-hover/40 p-3 text-xs leading-relaxed text-muted">
                    {detail.note}
                  </p>
                )}

                {detail.contributors.length > 0 && (
                  <div className="mt-5 space-y-2.5">
                    {detail.contributors.map((contributor) => (
                      <div key={contributor.key} className="rounded-lg border border-border/60 bg-surface-hover/30 p-3">
                        <div className="flex items-baseline justify-between gap-3">
                          <span className="text-sm font-medium text-ink">{contributor.label}</span>
                          <span className="shrink-0 font-mono text-sm font-bold text-primary">
                            +{contributor.points.toFixed(1)}
                          </span>
                        </div>
                        <p className="mt-1 text-xs leading-relaxed text-muted">{contributor.evidence}</p>
                      </div>
                    ))}

                    <div className="flex items-baseline justify-between border-t border-border pt-3">
                      <span className="text-sm font-semibold text-ink">Total</span>
                      <span className="font-mono text-sm font-bold text-ink">
                        {detail.contributors.reduce((sum, c) => sum + c.points, 0).toFixed(1)}
                      </span>
                    </div>
                  </div>
                )}

                {detail.unavailable_factors.length > 0 && (
                  <div className="mt-5 border-t border-border pt-4">
                    <p className="text-[10px] font-bold uppercase tracking-widest text-muted">
                      Not included in this score
                    </p>
                    <div className="mt-2 space-y-2">
                      {detail.unavailable_factors.map((factor) => (
                        <div key={factor.key} className="text-xs">
                          <span className="text-ink/80">{factor.label}</span>
                          <p className="mt-0.5 leading-relaxed text-muted/80">{factor.reason}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </main>
    </>
  );
}

function bandOf(score: number): string {
  if (score >= 90) return "extreme";
  if (score >= 70) return "critical";
  if (score >= 40) return "high";
  if (score >= 20) return "medium";
  if (score > 0) return "low";
  return "none";
}

function Stat({
  icon, label, value, tone, hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string | undefined;
  tone: "critical" | "warn" | "neutral";
  hint?: string;
}) {
  const toneClass = {
    critical: "text-critical",
    warn: "text-orange-500",
    neutral: "text-primary",
  }[tone];

  return (
    <div className="rounded-xl border border-border bg-surface p-4" title={hint}>
      <div className="flex items-center gap-2 text-muted">
        <span className={toneClass}>{icon}</span>
        <span className="text-[10px] font-bold uppercase tracking-widest">{label}</span>
      </div>
      <p className="mt-2 font-mono text-2xl font-bold text-ink">{value ?? "—"}</p>
    </div>
  );
}
