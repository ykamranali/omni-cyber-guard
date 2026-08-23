"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertCircle, Radio, ShieldOff, Zap } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Live activity feed.
 *
 * Shows only events the passive monitor actually observed on this network. An
 * earlier version injected a rotating list of invented events ("Automated
 * firewall rule applied", "1,402 new signatures loaded") every few seconds so
 * the panel always looked busy. Those were removed: a quiet network reads as
 * quiet, and an offline monitor says so.
 *
 * The query key is `["threat-intel"]`, which the WebSocket provider invalidates
 * when the worker reports a threat event — so a new observation appears as soon
 * as it happens rather than up to fifteen seconds later. The interval remains
 * as a fallback for when the socket is down, which is exactly the situation
 * where a stale feed would be most misleading.
 */

interface ObservedEvent {
  id: string;
  title?: string;
  description?: string;
  severity: string;
  timestamp?: string | null;
  source_ip?: string;
  destination_ip?: string;
}

interface ThreatIntelResponse {
  latest_advisories: ObservedEvent[];
  passive_monitor: { available: boolean; running: boolean; reason?: string };
}

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

export function ActivityTicker() {
  const { data, isLoading, isError } = useQuery<ThreatIntelResponse>({
    queryKey: ["threat-intel"],
    queryFn: () => api.get<ThreatIntelResponse>("/threat-intel"),
    refetchInterval: 15_000,
    retry: false,
  });

  const monitor = data?.passive_monitor;
  const events = data?.latest_advisories ?? [];
  const monitorOffline = isError || !monitor?.available || !monitor?.running;

  return (
    <div className="relative flex h-48 flex-col gap-2 overflow-hidden bg-surface/50 p-4">
      <div className="pointer-events-none absolute left-0 top-0 z-10 h-8 w-full bg-gradient-to-b from-surface/50 to-transparent" />
      <div className="pointer-events-none absolute bottom-0 left-0 z-10 h-8 w-full bg-gradient-to-t from-surface/50 to-transparent" />

      {!isLoading && events.length === 0 && (
        <div className="flex h-full flex-col items-center justify-center gap-2 px-4 text-center">
          <ShieldOff size={20} className="text-muted/60" />
          <p className="text-xs leading-relaxed text-muted">
            {monitorOffline
              ? monitor?.reason ||
                "Passive monitoring is not running, so nothing on this network is being observed. An empty feed here means nothing is being seen — not that nothing is happening."
              : "Capture is running and has observed no events in the current window."}
          </p>
        </div>
      )}

      {events.slice(0, 10).map((event, index) => (
        <div
          key={event.id}
          className="flex items-center gap-3 border-l-2 border-border/50 py-1 pl-3 text-xs transition-all duration-500 ease-out"
          style={{ opacity: 1 - index * 0.08 }}
        >
          <span className="w-20 shrink-0 font-mono text-muted/70">
            {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : "—"}
          </span>
          <div className="shrink-0 rounded border border-border/50 bg-surface p-1 shadow-glass">
            {event.severity?.toLowerCase() === "critical" ? (
              <AlertCircle size={14} className="text-critical" />
            ) : event.severity?.toLowerCase() === "high" ? (
              <Zap size={14} className="text-high" />
            ) : (
              <Radio size={14} className="text-primary" />
            )}
          </div>
          <span
            className={cn(
              "shrink-0 font-mono font-semibold uppercase tracking-wider",
              severityTone(event.severity),
            )}
          >
            [{event.severity}]
          </span>
          <span className="truncate text-ink/80">
            {event.title || "Network event"}
            {event.source_ip && (
              <span className="ml-2 font-mono text-muted">
                {event.source_ip}
                {event.destination_ip ? ` → ${event.destination_ip}` : ""}
              </span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}
