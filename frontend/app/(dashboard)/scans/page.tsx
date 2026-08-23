"use client";

import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, Radar, Loader2, CheckCircle2, XCircle, Circle, ShieldAlert,
  ShieldCheck, Server, ChevronDown, ChevronUp, Trash2,
} from "lucide-react";

import { Topbar } from "@/components/layout/topbar";
import { WorkerStatusBanner } from "@/components/system/worker-status-banner";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";

interface ScanScheduleOut {
  id: string;
  name: string;
  target_cidr: string;
  cron_expression: string;
  is_active: boolean;
  created_at: string;
}

interface ScanJobOut {
  id: string;
  target_cidr: string;
  scan_type: string;
  engine: string;
  status: "queued" | "running" | "completed" | "failed" | "canceled";
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
  canceled: { icon: <XCircle size={15} />, label: "Canceled", color: "text-muted" },
};

interface ScanEngine {
  name: string;
  adapter_version: string;
  description: string;
  capabilities: string[];
  requires_credential: boolean;
  available: boolean;
  summary: string;
  remediation: string;
  tool_version: string | null;
}

interface CredentialSummary {
  id: string;
  name: string;
  credential_type: string;
  username: string;
}

interface AuthorizationCheck {
  authorized: boolean;
  matched_network: { id: string; name: string; cidr: string } | null;
  message: string;
}

export default function ScanCenterPage() {
  const queryClient = useQueryClient();
  const [cidr, setCidr] = useState("");
  const [engine, setEngine] = useState("nmap");
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [confirmedAuthorized, setConfirmedAuthorized] = useState(false);
  const [credentialId, setCredentialId] = useState("");

  const { data: scans, isLoading, isError } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<ScanJobOut[]>("/scans"),
    refetchInterval: (query) =>
      (query.state.data || []).some((s) => s.status === "queued" || s.status === "running") ? 3000 : false,
  });

  /**
   * Engine availability comes from the adapters themselves. Each one probes for
   * its own binary or library, so an engine whose tool is missing is disabled
   * here with the command that installs it — rather than being offered and
   * failing, or appearing to run and producing nothing.
   */
  const { data: engineReport } = useQuery({
    queryKey: ["scan-engines"],
    queryFn: () => api.get<{ engines: ScanEngine[] }>("/scans/engines"),
  });
  const engines = engineReport?.engines ?? [];
  const selectedEngine = engines.find((e) => e.name === engine);

  const { data: credentials = [] } = useQuery({
    queryKey: ["credentials"],
    queryFn: () => api.get<CredentialSummary[]>("/credentials"),
    // Only organization administrators may enumerate credentials; a 403 here is
    // expected for other roles and simply means no picker is shown.
    retry: false,
    throwOnError: false,
  });

  const { data: schedules, isLoading: isLoadingSchedules } = useQuery({
    queryKey: ["schedules"],
    queryFn: () => api.get<ScanScheduleOut[]>("/schedules"),
  });

  /**
   * Ask the backend whether this target falls inside a range someone declared
   * as authorized scope. The operator is told what the platform actually knows
   * rather than being asked to tick a box with nothing behind it.
   */
  const trimmedTarget = cidr.trim();
  const isNetworkTarget = /^[0-9.]+(\/\d{1,2})?$/.test(trimmedTarget);

  const { data: authorization } = useQuery({
    queryKey: ["scan-authorization", trimmedTarget],
    queryFn: () =>
      api.get<AuthorizationCheck>(
        `/networks/authorization-check?target=${encodeURIComponent(trimmedTarget)}`
      ),
    enabled: isNetworkTarget && trimmedTarget.length >= 7,
    retry: false,
  });

  const [selectedScanIds, setSelectedScanIds] = useState<Set<string>>(new Set());
  
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleCidr, setScheduleCidr] = useState("");
  const [scheduleCron, setScheduleCron] = useState("0 2 * * *");
  const [scheduleError, setScheduleError] = useState<string | null>(null);

  const createSchedule = useMutation({
    mutationFn: () => api.post<ScanScheduleOut>("/schedules", { name: scheduleName, target_cidr: scheduleCidr, cron_expression: scheduleCron }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["schedules"] });
      setScheduleError(null);
      setScheduleName("");
      setScheduleCidr("");
    },
    onError: (err) => setScheduleError(err instanceof ApiError ? err.message : "Failed to create schedule"),
  });

  const deleteSchedule = useMutation({
    mutationFn: (id: string) => api.delete(`/schedules/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["schedules"] }),
  });
  
  const startScan = useMutation({
    mutationFn: () =>
      api.post<ScanJobOut>("/scans", {
        target_cidr: cidr,
        engine,
        credential_profile_id: credentialId || null,
        // The operator's affirmation at launch. The backend requires it and
        // separately checks the target against declared authorized scope; the
        // checkbox below is what this carries.
        authorization_confirmed: confirmedAuthorized,
      }),
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
    mutationFn: (ids: string[]) =>
      api.delete<{ deleted: string[]; skipped: { id: string; reason: string }[] }>(
        "/scans/bulk",
        ids,
      ),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setSelectedScanIds(new Set());
      setExpandedId(null);
      // Bulk delete used to return 204 and silently skip whatever it could not
      // remove, so selecting ten rows could delete none of them and look like
      // it had worked.
      if (result?.skipped?.length) {
        setError(
          `${result.deleted.length} deleted. ${result.skipped.length} skipped: ` +
            result.skipped.map((item) => item.reason).join(" "),
        );
      } else {
        setError(null);
      }
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
        {/* A scan cannot progress without a worker. Saying so here is the
            difference between "queued" meaning "starting shortly" and
            "queued" meaning "nothing will ever pick this up". */}
        <WorkerStatusBanner />
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
            Each engine wraps a real tool and reports whether it can run on this worker.
            An engine whose tool is missing is disabled below, with what to install.
          </p>

          <div className="mb-4 grid gap-3 sm:grid-cols-2">
            {engines.length === 0 && (
              <p className="text-sm text-muted">Loading engines…</p>
            )}
            {engines.map((eng) => {
              const selected = engine === eng.name;
              return (
                <button
                  key={eng.name}
                  type="button"
                  onClick={() => eng.available && setEngine(eng.name)}
                  disabled={!eng.available}
                  className={`rounded-xl border p-4 text-left transition-all ${
                    selected
                      ? "border-primary bg-primary/10 shadow-neon"
                      : eng.available
                        ? "border-border bg-surface-hover/30 hover:border-primary/50"
                        : "cursor-not-allowed border-border bg-surface opacity-60"
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <Radar
                      size={18}
                      className={selected ? "mt-0.5 animate-pulse text-primary" : "mt-0.5 text-muted"}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <h4 className="text-sm font-bold text-ink">{eng.name}</h4>
                        {eng.requires_credential && (
                          <span className="rounded border border-purple-500/40 bg-purple-500/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-purple-400">
                            credentialed
                          </span>
                        )}
                        {!eng.available && (
                          <span className="rounded border border-border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-muted">
                            not configured
                          </span>
                        )}
                      </div>
                      <p className="mt-0.5 text-xs text-muted">{eng.description}</p>
                      {eng.available ? (
                        eng.tool_version && (
                          <p className="mt-1 font-mono text-[10px] text-muted/70">{eng.tool_version}</p>
                        )
                      ) : (
                        <p className="mt-1.5 text-[11px] leading-relaxed text-orange-400/90">
                          {eng.summary} {eng.remediation}
                        </p>
                      )}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          {selectedEngine?.requires_credential && (
            <div className="mb-4 rounded-xl border border-purple-500/30 bg-purple-500/5 p-4">
              <label className="mb-1.5 block text-xs font-medium text-ink">
                Credential profile
              </label>
              <select
                value={credentialId}
                onChange={(e) => setCredentialId(e.target.value)}
                className="w-full rounded-md border border-border bg-surface px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none"
              >
                <option value="">Select a credential…</option>
                {credentials.map((credential) => (
                  <option key={credential.id} value={credential.id}>
                    {credential.name} ({credential.username || credential.credential_type})
                  </option>
                ))}
              </select>
              <p className="mt-1.5 text-[11px] leading-relaxed text-muted">
                {credentials.length === 0
                  ? "No credentials available to you. An organization administrator can add one under Administration → Credentials."
                  : "The secret is decrypted once, at scan time, and the access is written to the audit log with this target."}
              </p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[240px] flex-1">
              <label className="mb-1 block text-xs text-muted">Target CIDR or URL</label>
              <Input
                required
                placeholder="e.g. 192.168.1.0/24 or https://target.local"
                value={cidr}
                onChange={(e) => {
                  setCidr(e.target.value);
                  setConfirmedAuthorized(false);
                }}
              />
            </div>
            <Button
              type="submit"
              disabled={
                startScan.isPending ||
                !confirmedAuthorized ||
                !selectedEngine?.available ||
                (selectedEngine?.requires_credential === true && !credentialId)
              }
            >
              {startScan.isPending ? "Starting…" : "Start Scan"}
            </Button>
          </form>

          {trimmedTarget.length >= 7 && (
            <div
              className={`mt-4 flex gap-3 rounded-xl border p-4 ${
                authorization?.authorized
                  ? "border-green-500/30 bg-green-500/5"
                  : "border-orange-500/30 bg-orange-500/5"
              }`}
            >
              {authorization?.authorized ? (
                <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-green-500" />
              ) : (
                <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-orange-500" />
              )}
              <div className="space-y-2">
                <p className="text-sm font-semibold text-ink">
                  You are about to assess <span className="font-mono">{trimmedTarget}</span>
                </p>
                <p className="text-sm leading-relaxed text-muted">
                  {authorization
                    ? authorization.message
                    : isNetworkTarget
                      ? "Checking this target against your declared networks…"
                      : "This target is not an IP range, so it cannot be matched against your declared networks."}
                </p>
                <label className="flex cursor-pointer items-start gap-2.5 pt-1">
                  <input
                    type="checkbox"
                    checked={confirmedAuthorized}
                    onChange={(e) => setConfirmedAuthorized(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span className="text-sm text-ink/90">
                    I confirm I am authorized to assess this target.
                    <span className="mt-0.5 block text-xs text-muted">
                      Recorded against your account in the audit log.
                    </span>
                  </span>
                </label>
              </div>
            </div>
          )}
          {error && (
            <p className="mt-3 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              {error}
            </p>
          )}
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Radar size={18} className="text-primary" />
              <CardTitle>Scheduled Scans (Recurring)</CardTitle>
            </div>
          </CardHeader>
          <p className="mb-4 text-sm text-muted">
            Configure automated, recurring scans using standard cron expressions (e.g. <code>0 2 * * *</code> for daily at 2 AM).
          </p>

          <form onSubmit={(e) => { e.preventDefault(); createSchedule.mutate(); }} className="flex flex-wrap items-end gap-3 mb-6">
            <div className="min-w-[150px] flex-1">
              <label className="mb-1 block text-xs text-muted">Schedule Name</label>
              <Input
                required
                placeholder="Daily Subnet Scan"
                value={scheduleName}
                onChange={(e) => setScheduleName(e.target.value)}
              />
            </div>
            <div className="min-w-[150px] flex-1">
              <label className="mb-1 block text-xs text-muted">Target CIDR</label>
              <Input
                required
                placeholder="192.168.1.0/24"
                value={scheduleCidr}
                onChange={(e) => setScheduleCidr(e.target.value)}
              />
            </div>
            <div className="min-w-[120px] flex-1">
              <label className="mb-1 block text-xs text-muted">Cron Expression</label>
              <Input
                required
                placeholder="0 2 * * *"
                value={scheduleCron}
                onChange={(e) => setScheduleCron(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={createSchedule.isPending}>
              {createSchedule.isPending ? "Saving…" : "Create Schedule"}
            </Button>
          </form>

          {scheduleError && (
            <p className="mb-4 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
              {scheduleError}
            </p>
          )}

          {schedules && schedules.length > 0 && (
            <div className="divide-y divide-border/60 border-t border-border mt-4">
              {schedules.map((s) => (
                <div key={s.id} className="flex items-center justify-between py-3">
                  <div>
                    <p className="text-sm font-medium text-ink">{s.name}</p>
                    <p className="text-xs text-muted">Target: {s.target_cidr} · Cron: <code>{s.cron_expression}</code></p>
                  </div>
                  <button
                    onClick={() => {
                      if (confirm("Are you sure you want to delete this schedule?")) {
                        deleteSchedule.mutate(s.id);
                      }
                    }}
                    disabled={deleteSchedule.isPending}
                    className="rounded-md p-1.5 text-muted hover:bg-critical/10 hover:text-critical"
                    title="Delete Schedule"
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              ))}
            </div>
          )}
          {schedules && schedules.length === 0 && (
            <p className="text-sm text-muted mt-2">No schedules created yet.</p>
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
                            <p className="text-sm font-medium text-ink flex items-center gap-2">
                              {s.target_cidr} 
                              <span className="px-2 py-0.5 rounded-full bg-surface-hover border border-border text-[10px] uppercase font-bold tracking-wider text-primary">
                                {s.engine}
                              </span>
                            </p>
                            <p className="text-xs text-muted">
                              {new Date(s.created_at).toLocaleString()}
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
                        {s.status === "canceled" && (
                          <div className="text-sm text-muted">
                            {s.error_message || "This scan was canceled by an operator."}
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
