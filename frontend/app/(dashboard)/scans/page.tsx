"use client";

import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Radar, Loader2, CheckCircle2, XCircle, Circle, ShieldAlert, Server, ChevronDown, ChevronUp, Trash2
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

  const [selectedScanIds, setSelectedScanIds] = useState<Set<string>>(new Set());
  
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

  const cancelScan = useMutation({
    mutationFn: (id: string) => api.post(`/scans/${id}/cancel`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const deleteScan = useMutation({
    mutationFn: (id: string) => api.delete(`/scans/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setExpandedId(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Failed to delete scan"),
  });

  const deleteBulkScans = useMutation({
    mutationFn: (ids: string[]) => api.delete("/scans/bulk", ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setSelectedScanIds(new Set());
      setExpandedId(null);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Failed to delete scans"),
  });

  const toggleScanSelection = (id: string) => {
    const newSet = new Set(selectedScanIds);
    if (newSet.has(id)) newSet.delete(id);
    else newSet.add(id);
    setSelectedScanIds(newSet);
  };

  const toggleAllScans = () => {
    if (!scans) return;
    if (selectedScanIds.size === scans.length) {
      setSelectedScanIds(new Set());
    } else {
      setSelectedScanIds(new Set(scans.map(s => s.id)));
    }
  };

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
          <div className="flex items-center justify-between border-b border-border px-5 py-4">
            <div className="flex items-center gap-3">
              {scans && scans.length > 0 && (
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
                  checked={selectedScanIds.size === scans.length}
                  onChange={toggleAllScans}
                />
              )}
              <h3 className="text-sm font-medium text-ink">Scan History</h3>
            </div>
            {selectedScanIds.size > 0 && (
              <Button
                variant="danger"
                size="sm"
                onClick={() => {
                  if (confirm(`Are you sure you want to delete ${selectedScanIds.size} scan(s)? This will also permanently delete all associated assets and findings.`)) {
                    deleteBulkScans.mutate(Array.from(selectedScanIds));
                  }
                }}
                disabled={deleteBulkScans.isPending}
              >
                {deleteBulkScans.isPending ? "Deleting..." : `Delete Selected (${selectedScanIds.size})`}
              </Button>
            )}
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
                    <div className="flex w-full items-center gap-4">
                      <input
                        type="checkbox"
                        className="h-4 w-4 rounded border-border text-primary focus:ring-primary/40"
                        checked={selectedScanIds.has(s.id)}
                        onChange={() => toggleScanSelection(s.id)}
                      />
                      <button
                        className="flex flex-1 items-center justify-between gap-4 text-left"
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
                      <button
                        onClick={() => {
                          if (confirm("Are you sure you want to delete this scan?")) {
                            deleteScan.mutate(s.id);
                          }
                        }}
                        disabled={deleteScan.isPending}
                        className="rounded-md p-1.5 text-muted hover:bg-critical/10 hover:text-critical"
                        title="Delete Scan"
                      >
                        <Trash2 size={15} />
                      </button>
                    </div>

                    {expandedId === s.id && (
                      <div className="ml-7 mt-3 rounded-lg bg-ink p-4 shadow-inner">
                        {s.status === "failed" && (
                          <div className="text-sm text-critical">
                            {s.error_message || "The scan failed for an unknown reason."}
                          </div>
                        )}
                        {(s.status === "queued" || s.status === "running" || s.status === "completed") && (
                          <div className="font-mono text-xs">
                            <div className="mb-2 flex items-center justify-between border-b border-white/10 pb-2 text-white/50">
                              <div className="flex items-center gap-2">
                                <Radar size={12} className={s.status === "running" ? "animate-pulse text-primary" : ""} />
                                <span>Live Scan Terminal Feed</span>
                              </div>
                              <div className="flex items-center gap-2">
                                {s.status === "running" && (
                                  <button
                                    onClick={() => cancelScan.mutate(s.id)}
                                    disabled={cancelScan.isPending}
                                    className="rounded border border-critical/50 bg-critical/10 px-2 py-0.5 text-[10px] uppercase tracking-wider text-critical hover:bg-critical/20"
                                  >
                                    Stop Scan
                                  </button>
                                )}
                              </div>
                            </div>
                            <pre className="max-h-64 overflow-y-auto whitespace-pre-wrap text-green-400">
                              {s.raw_summary || (s.status === "queued" ? "Queued for scanning..." : "Initializing scan engine...")}
                            </pre>
                            {s.status === "running" && (
                              <div className="mt-2 flex items-center gap-2 text-primary animate-pulse">
                                <span className="h-2 w-2 rounded-full bg-primary" /> Scanning in progress...
                              </div>
                            )}
                          </div>
                        )}
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
