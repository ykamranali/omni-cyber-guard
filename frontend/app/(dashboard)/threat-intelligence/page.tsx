"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Activity, AlertTriangle, Database, ExternalLink, RefreshCw, Radio,
  Satellite, ShieldAlert, ShieldOff, Zap,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Threat intelligence.
 *
 * The page read `entries`, `configured`, `sources` and `total_records` from the
 * top level of `/threat-intel`. The API returns those nested under
 * `cve_catalogue`, alongside a separate `latest_advisories` list of events the
 * passive monitor actually observed on the network. So `data.entries` was
 * `undefined` and the page rendered nothing at all.
 *
 * The two halves are shown separately on purpose, because they are different
 * kinds of claim. `latest_advisories` is **your network**: traffic this
 * deployment observed. The catalogue is **the world**: CVEs published
 * elsewhere, which say nothing about whether you are affected. Merging them
 * into one feed would blur exactly the line that matters.
 */

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/i;

interface ObservedEvent {
  id: string;
  title?: string;
  description?: string;
  severity: string;
  timestamp?: string | null;
  source_ip?: string;
  destination_ip?: string;
}

interface CatalogueEntry {
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

interface CveCatalogue {
  configured: boolean;
  sources: string[];
  last_synced_at: string | null;
  total_records: number;
  entries: CatalogueEntry[];
  message: string;
}

interface ThreatIntelResponse {
  global_risk_level: "MONITOR_UNAVAILABLE" | "ELEVATED" | "MONITORING" | "QUIET";
  observed_events: number;
  latest_advisories: ObservedEvent[];
  passive_monitor: { available: boolean; running: boolean; reason?: string };
  cve_catalogue: CveCatalogue;
}

const POSTURE: Record<string, { label: string; detail: string; className: string }> = {
  MONITOR_UNAVAILABLE: {
    label: "Monitor unavailable",
    detail:
      "Passive capture is not running, so nothing on your network is being observed. This is not the same as a quiet network.",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-400",
  },
  ELEVATED: {
    label: "Elevated",
    detail: "Critical-severity activity was observed in the current window.",
    className: "border-red-500/30 bg-red-500/10 text-red-400",
  },
  MONITORING: {
    label: "Monitoring",
    detail: "Capture is running and has observed activity.",
    className: "border-sky-500/30 bg-sky-500/10 text-sky-400",
  },
  QUIET: {
    label: "Quiet",
    detail: "Capture is running and has observed nothing in the current window.",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  },
};

function severityTone(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "text-critical";
    case "high":
      return "text-high";
    case "medium":
      return "text-medium";
    case "low":
      return "text-low";
    default:
      return "text-muted";
  }
}

export default function ThreatIntelligencePage() {
  const { data, isLoading, error } = useQuery<ThreatIntelResponse>({
    queryKey: ["threat-intel"],
    queryFn: () => api.get<ThreatIntelResponse>("/threat-intel"),
    // The passive monitor writes events continuously. This is the live view of
    // your own network, so it refreshes on its own; the WebSocket also
    // invalidates it when the worker reports an event.
    refetchInterval: 15_000,
  });

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
          <p className="text-sm text-muted">Loading threat intelligence…</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-400">
          <AlertTriangle className="h-5 w-5" />
          {error instanceof ApiError
            ? error.message
            : "Threat intelligence could not be loaded."}
        </div>
      </div>
    );
  }

  const posture = POSTURE[data.global_risk_level] ?? POSTURE.QUIET;
  const catalogue = data.cve_catalogue;
  const monitor = data.passive_monitor;

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-ink">
            <Satellite className="h-8 w-8 text-primary" />
            Threat Intelligence
          </h1>
          <p className="mt-2 text-muted">
            What was observed on your network, and what has been published
            elsewhere. Kept separate.
          </p>
        </div>

        <div
          className={cn(
            "flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium",
            posture.className,
          )}
        >
          <Activity className="h-4 w-4" />
          {posture.label}
        </div>
      </div>

      <p className="text-xs text-muted">{posture.detail}</p>

      {/* ---------------------------------------------------------------- */}
      <section className="rounded-xl border border-border bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-4">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold text-ink">Observed on your network</h2>
          </div>
          <p className="text-xs text-muted">
            {data.observed_events} event(s) in the current window · refreshes
            automatically
          </p>
        </div>

        {!monitor.available || !monitor.running ? (
          <div className="flex flex-col items-center gap-2 p-10 text-center">
            <ShieldOff className="h-8 w-8 text-muted/50" />
            <p className="text-sm text-ink/80">Passive monitoring is not running</p>
            <p className="max-w-lg text-xs leading-relaxed text-muted">
              {monitor.reason ||
                "Capture needs CAP_NET_RAW and a worker that can see the segment it is meant to observe. Nothing on your network is being watched — an empty feed here means nothing is being seen, not that nothing is happening."}
            </p>
          </div>
        ) : data.latest_advisories.length === 0 ? (
          <div className="p-10 text-center text-sm text-muted">
            Capture is running and has observed nothing in the current window.
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {data.latest_advisories.map((event) => (
              <div key={event.id} className="flex items-start gap-3 px-5 py-3">
                <Zap className={cn("mt-0.5 h-4 w-4 shrink-0", severityTone(event.severity))} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={cn(
                        "text-[10px] font-bold uppercase tracking-wider",
                        severityTone(event.severity),
                      )}
                    >
                      {event.severity}
                    </span>
                    <span className="text-sm text-ink">{event.title || "Network event"}</span>
                  </div>
                  {event.description && (
                    <p className="mt-0.5 text-xs text-muted">{event.description}</p>
                  )}
                  {(event.source_ip || event.destination_ip) && (
                    <p className="mt-0.5 font-mono text-[11px] text-muted">
                      {event.source_ip} → {event.destination_ip}
                    </p>
                  )}
                </div>
                <span className="shrink-0 text-[11px] text-muted">
                  {event.timestamp
                    ? formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })
                    : ""}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ---------------------------------------------------------------- */}
      <section className="rounded-xl border border-border bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-4">
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold text-ink">
              Published vulnerability catalogue
            </h2>
          </div>
          <p className="text-xs text-muted">
            {catalogue.total_records.toLocaleString()} CVE(s) held locally
            {catalogue.last_synced_at &&
              ` · synced ${formatDistanceToNow(new Date(catalogue.last_synced_at), {
                addSuffix: true,
              })}`}
          </p>
        </div>

        <p className="border-b border-border/50 px-5 py-2 text-[11px] text-muted">
          Sources: {catalogue.sources.join(", ")}. These are advisories published
          to the world — appearing here does not mean your estate is affected.
          Correlation against your own inventory happens on the Vulnerabilities
          page.
        </p>

        {!catalogue.configured ? (
          <div className="flex flex-col items-center gap-3 p-10 text-center">
            <Database className="h-8 w-8 text-muted/40" />
            <p className="text-sm text-ink/80">Catalogue not synchronised</p>
            <p className="max-w-lg text-xs text-muted">{catalogue.message}</p>
            <Link
              href="/cve-intelligence"
              className="mt-1 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground"
            >
              Open CVE Intelligence
            </Link>
          </div>
        ) : catalogue.entries.length === 0 ? (
          <div className="p-10 text-center text-sm text-muted">
            The catalogue holds no recently published entries.
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {catalogue.entries.map((entry) => (
              <div key={entry.id} className="px-5 py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-semibold text-primary">{entry.title}</h3>
                      {entry.known_exploited && (
                        <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rose-500">
                          <ShieldAlert className="h-3 w-3" /> CISA KEV
                        </span>
                      )}
                      <span
                        className={cn(
                          "text-[10px] font-bold uppercase tracking-wider",
                          severityTone(entry.severity),
                        )}
                      >
                        {entry.severity}
                      </span>
                    </div>

                    <p className="mt-1 line-clamp-2 max-w-4xl text-xs text-muted">
                      {entry.description}
                    </p>

                    <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                      {entry.cvss !== null && (
                        <span className="rounded-md border border-border bg-surface-hover px-2 py-1">
                          <span className="text-muted">CVSS </span>
                          <span className="font-mono font-bold text-ink">
                            {entry.cvss.toFixed(1)}
                          </span>
                        </span>
                      )}
                      {entry.epss !== null && (
                        <span className="rounded-md border border-border bg-surface-hover px-2 py-1">
                          <span className="text-muted">EPSS </span>
                          <span className="font-mono font-bold text-ink">
                            {(entry.epss * 100).toFixed(2)}%
                          </span>
                        </span>
                      )}
                      {entry.tags.map((tag) => (
                        <span
                          key={tag}
                          className="rounded-md border border-border bg-surface-hover px-2 py-1 font-mono text-ink/80"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="shrink-0 text-right">
                    <p className="text-[11px] text-muted">
                      {entry.timestamp
                        ? formatDistanceToNow(new Date(entry.timestamp), { addSuffix: true })
                        : "Publication date unknown"}
                    </p>
                    {CVE_PATTERN.test(entry.title) && (
                      <Link
                        href={`/cve-intelligence?search=${encodeURIComponent(
                          entry.title.match(CVE_PATTERN)![0],
                        )}`}
                        className="mt-2 inline-flex items-center gap-1.5 text-xs font-medium text-primary hover:text-primary/80"
                      >
                        View details <ExternalLink className="h-3 w-3" />
                      </Link>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
