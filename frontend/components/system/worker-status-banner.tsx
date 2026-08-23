"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Clock } from "lucide-react";
import { api } from "@/lib/api";

/**
 * Says out loud when background processing is not running.
 *
 * A queued scan that no worker will ever take looks exactly like a queued scan
 * that is about to start — the row says QUEUED, the page says "queued for
 * scanning", and both are true. Nothing anywhere said that nothing was going to
 * happen. The same silence covers scheduled scans, CVE synchronisation and
 * nightly snapshots when the scheduler is absent.
 *
 * The banner shows only when there is something wrong, so a healthy deployment
 * sees nothing.
 */

interface WorkerHealth {
  broker: string;
  workers_online: number;
  worker_names: string[];
  healthy: boolean;
  scheduler_running: boolean | null;
  scheduler_evidence: string;
  error: string;
  remediation: string;
  scheduler_remediation: string;
}

export function WorkerStatusBanner() {
  const { data } = useQuery<WorkerHealth>({
    queryKey: ["system", "workers"],
    queryFn: () => api.get<WorkerHealth>("/system/workers"),
    refetchInterval: 60_000,
    retry: false,
  });

  if (!data) return null;

  const workerDown = !data.healthy;
  // `null` means no evidence either way — a new deployment looks identical to a
  // dead scheduler, and claiming it is broken would be a guess.
  const schedulerDown = data.scheduler_running === false;

  if (!workerDown && !schedulerDown) return null;

  return (
    <div className="space-y-3">
      {workerDown && (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/5 p-4">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-red-400" />
          <div className="min-w-0 text-sm">
            <p className="font-medium text-red-400">
              No background worker is running
            </p>
            <p className="mt-1 text-ink/90">{data.remediation}</p>
            {data.error && (
              <p className="mt-1 text-xs text-muted">
                Broker {data.broker}: {data.error}
              </p>
            )}
          </div>
        </div>
      )}

      {schedulerDown && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
          <Clock className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
          <div className="min-w-0 text-sm">
            <p className="font-medium text-amber-400">
              Nothing on a schedule is running
            </p>
            <p className="mt-1 text-ink/90">{data.scheduler_remediation}</p>
            <p className="mt-1 text-xs text-muted">{data.scheduler_evidence}</p>
          </div>
        </div>
      )}
    </div>
  );
}
