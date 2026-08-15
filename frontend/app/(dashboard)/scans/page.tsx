"use client";

import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Radar, Loader2, CheckCircle2, XCircle, Circle, ShieldAlert, Server, ChevronDown, ChevronUp,
} from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";

interface ScanJobOut {
  id: string;
  target_cidr: string;
  scan_type: string;
  status: "queued" | "running" | "completed" | "failed";
  hosts_discovered: number;
  findings_generated: number;
  error_message: string | null;
  raw_summary: string;
  created_at: string;
  updated_at: string;
}

const STATUS_META: Record<string, { icon: JSX.Element; label: string; color: string }> = {
  completed: { icon: <CheckCircle2 size={15} />, label: "Completed", color: "text-low" },
  running: { icon: <Loader2 size={15} className="animate-spin" />, label: "Running", color: "text-primary" },
  queued: { icon: <Circle size={15} />, label: "Queued", color: "text-muted" },
  failed: { icon: <XCircle size={15} />, label: "Failed", color: "text-critical" },
};

export default function ScanCenterPage() {
  const queryClient = useQueryClient();
  const [cidr, setCidr] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data: scans, isLoading, isError } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<ScanJobOut[]>("/scans"),
    refetchInterval: (query) =>
      (query.state.data || []).some((s) => s.status === "queued" || s.status === "running") ? 3000 : false,
  });

  const startScan = useMutation({
    mutationFn: () => api.post<ScanJobOut>("/scans", { target_cidr: cidr }),
    onSuccess: (job) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setExpandedId(job.id);
      setError(null);
      setCidr("");
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Failed to start scan"),
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    startScan.mutate();
  }

  const runningCount = (scans || []).filter((s) => s.status === "queued" || s.status === "running").length;

  return (
    <>
      <Topbar title="Scan Center" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Radar size={18} className="text-primary" />
              <CardTitle>New Network Scan</CardTitle>
            </div>
            {runningCount > 0 && (
              <span className="flex items-center gap-1.5 text-xs text-primary">
                <Loader2 size={12} className="animate-spin" /> {runningCount} scan(s) in progress
              </span>
            )}
          </CardHeader>

          <p className="mb-4 text-sm text-muted">
            Runs a real, nmap-backed host discovery and port/service scan — the same kind of authorized
            reconnaissance tools like Nessus or OpenVAS perform. Only private (RFC1918) or loopback ranges
            are permitted; public IP ranges are rejected before anything is sent.{" "}
            <strong className="text-ink/80">Only scan networks you own or are explicitly authorized to assess.</strong>{" "}
            Discovered hosts are added to your asset inventory automatically, and risky exposed services
            (Telnet, RDP, exposed databases, etc.) become real findings with remediation guidance.
          </p>

          <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[240px] flex-1">
              <label className="mb-1 block text-xs text-muted">Target CIDR range</label>
              <Input
                required
                placeholder="e.g. 192.168.1.0/24 (find your own with ipconfig / ifconfig)"
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={startScan.isPending}>
              {startScan.isPending ? "Starting…" : "Start Scan"}
            </Button>
          </form>
          {error && (
            <p className="mt-3 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              {error}
            </p>
          )}
        </Card>

        <Card className="overflow-hidden p-0">
          <div className="border-b border-border px-5 py-4">
            <h3 className="text-sm font-medium text-ink">Scan History</h3>
          </div>

          {isLoading && <p className="p-6 text-sm text-muted">Loading scans…</p>}
          {isError && <p className="p-6 text-sm text-critical">Unable to load scan history from the API.</p>}
          {scans && scans.length === 0 && (
            <p className="p-6 text-sm text-muted">
              No scans yet. Start one above — for a first test, try scanning just your own machine
              (e.g. 127.0.0.1/32) or your local subnet.
            </p>
          )}

          {scans && scans.length > 0 && (
            <div className="divide-y divide-border/60">
              {scans.map((s) => {
                const meta = STATUS_META[s.status];
                return (
                  <div key={s.id} className="p-4">
                    <button
                      className="flex w-full items-center justify-between gap-4 text-left"
                      onClick={() => setExpandedId(expandedId === s.id ? null : s.id)}
                    >
                      <div className="flex items-center gap-3">
                        <span className={meta.color}>{meta.icon}</span>
                        <div>
                          <p className="text-sm font-medium text-ink">{s.target_cidr}</p>
                          <p className="text-xs text-muted">
                            {new Date(s.created_at).toLocaleString()} · {s.scan_type.replace(/_/g, " ")}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {s.status === "completed" && (
                          <>
                            <span className="flex items-center gap-1 text-xs text-ink/70">
                              <Server size={13} /> {s.hosts_discovered} host(s)
                            </span>
                            <span className="flex items-center gap-1 text-xs text-ink/70">
                              <ShieldAlert size={13} /> {s.findings_generated} finding(s)
                            </span>
                          </>
                        )}
                        <span className={`text-xs font-medium ${meta.color}`}>{meta.label}</span>
                        {expandedId === s.id ? <ChevronUp size={14} className="text-muted" /> : <ChevronDown size={14} className="text-muted" />}
                      </div>
                    </button>

                    {expandedId === s.id && (
                      <div className="ml-7 mt-3 rounded-lg bg-surface-hover/40 p-3 text-sm text-ink/75">
                        {s.status === "failed" && (s.error_message || "The scan failed for an unknown reason.")}
                        {s.status === "completed" && (s.raw_summary || "No summary recorded.")}
                        {(s.status === "queued" || s.status === "running") && "Scan is in progress — this page refreshes automatically."}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </main>
    </>
  );
}
