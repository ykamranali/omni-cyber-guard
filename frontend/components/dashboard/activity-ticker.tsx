"use client";

import { useEffect, useState } from "react";
import { AlertCircle, Radio, ShieldOff, Zap } from "lucide-react";
import { api } from "@/lib/api";

interface ActivityEvent {
  id: string;
  time: string;
  type: "threat" | "scan" | "defense" | "system";
  message: string;
}

interface ThreatIntelResponse {
  latest_advisories: {
    id: string;
    title: string;
    description: string;
    severity: string;
    timestamp: string;
  }[];
  passive_monitor: { available: boolean; running: boolean };
}

/**
 * Live activity feed.
 *
 * Shows only events the passive monitor actually observed. An earlier version
 * injected a rotating list of invented events ("Automated firewall rule
 * applied", "1,402 new signatures loaded") every few seconds so the panel
 * always looked busy. Those were removed: a quiet network now reads as quiet,
 * and an offline monitor says so.
 */
export function ActivityTicker() {
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [monitorOffline, setMonitorOffline] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const data = await api.get<ThreatIntelResponse>("/threat-intel");
        if (cancelled) return;

        setMonitorOffline(!data.passive_monitor?.running);
        setEvents(
          (data.latest_advisories ?? []).slice(0, 10).map((event) => ({
            id: event.id,
            time: new Date(event.timestamp).toLocaleTimeString(),
            type: "threat" as const,
            message: `[${event.severity}] ${event.title} — ${event.description}`,
          }))
        );
      } catch {
        if (!cancelled) setMonitorOffline(true);
      } finally {
        if (!cancelled) setLoaded(true);
      }
    };

    load();
    const interval = setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const iconFor = (type: string) => {
    switch (type) {
      case "threat":
        return <AlertCircle size={14} className="text-critical" />;
      case "scan":
        return <Radio size={14} className="text-primary" />;
      default:
        return <Zap size={14} className="text-muted" />;
    }
  };

  const colorFor = (type: string) => {
    switch (type) {
      case "threat":
        return "text-critical";
      case "scan":
        return "text-primary";
      default:
        return "text-muted";
    }
  };

  return (
    <div className="relative flex h-48 flex-col gap-2 overflow-hidden bg-surface/50 p-4">
      <div className="pointer-events-none absolute left-0 top-0 z-10 h-8 w-full bg-gradient-to-b from-surface/50 to-transparent" />
      <div className="pointer-events-none absolute bottom-0 left-0 z-10 h-8 w-full bg-gradient-to-t from-surface/50 to-transparent" />

      {loaded && events.length === 0 && (
        <div className="flex h-full flex-col items-center justify-center gap-2 text-center">
          <ShieldOff size={20} className="text-muted/60" />
          <p className="text-xs text-muted">
            {monitorOffline
              ? "Passive monitor is not running — no traffic is being observed."
              : "No network events observed in the current window."}
          </p>
        </div>
      )}

      {events.map((event, index) => (
        <div
          key={event.id}
          className="flex items-center gap-3 border-l-2 border-border/50 py-1 pl-3 text-xs transition-all duration-500 ease-out"
          style={{ opacity: 1 - index * 0.08 }}
        >
          <span className="w-20 font-mono text-muted/70">{event.time}</span>
          <div className="rounded border border-border/50 bg-surface p-1 shadow-glass">
            {iconFor(event.type)}
          </div>
          <span className={`font-mono font-semibold uppercase tracking-wider ${colorFor(event.type)}`}>
            [{event.type}]
          </span>
          <span className="truncate text-ink/80">{event.message}</span>
        </div>
      ))}
    </div>
  );
}
