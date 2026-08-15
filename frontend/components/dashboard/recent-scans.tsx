"use client";

import { Loader2, CheckCircle2, XCircle, Circle } from "lucide-react";

interface ScanJobOut {
  id: string;
  target_cidr: string;
  status: string;
  hosts_discovered: number;
  findings_generated: number;
  created_at: string;
}

const STATUS_ICON: Record<string, JSX.Element> = {
  completed: <CheckCircle2 size={14} className="text-low" />,
  running: <Loader2 size={14} className="animate-spin text-primary" />,
  queued: <Circle size={14} className="text-muted" />,
  failed: <XCircle size={14} className="text-critical" />,
};

export function RecentScans({ scans }: { scans: ScanJobOut[] }) {
  if (scans.length === 0) {
    return (
      <p className="text-xs text-muted">
        No scans have been run yet. Start one from the Assets page to discover real devices on your network.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {scans.slice(0, 5).map((scan) => (
        <div key={scan.id} className="flex items-start gap-2 text-sm">
          {STATUS_ICON[scan.status] || <Circle size={14} className="text-muted" />}
          <div className="min-w-0 flex-1">
            <p className="truncate text-ink/85">{scan.target_cidr}</p>
            <p className="text-xs text-muted">
              {scan.status === "completed"
                ? `${scan.hosts_discovered} host(s), ${scan.findings_generated} new finding(s)`
                : scan.status}
              {" · "}
              {new Date(scan.created_at).toLocaleString()}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
