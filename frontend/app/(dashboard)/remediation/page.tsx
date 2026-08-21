"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, CheckCircle2, Clock, FileWarning, Hourglass, Info, ShieldCheck, XCircle,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { Topbar } from "@/components/layout/topbar";
import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/modal";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Task {
  id: string;
  finding_id: string;
  title: string;
  description: string;
  status: string;
  priority: string;
  due_date: string | null;
  sla_days: number | null;
  fixed_at: string | null;
  verified_at: string | null;
  verified_by_scan_job_id: string | null;
  notes: string;
  is_overdue: boolean;
  days_until_due: number | null;
  finding_severity: string | null;
  finding_cve_id: string | null;
  asset_hostname: string | null;
  assigned_to_name: string | null;
}

interface Acceptance {
  id: string;
  finding_id: string;
  reason: string;
  compensating_controls: string;
  expires_at: string;
  status: string;
  days_until_expiry: number | null;
  finding_title: string | null;
  approved_by_name: string | null;
  revocation_reason: string;
}

interface Metrics {
  open_tasks: number;
  overdue_tasks: number;
  awaiting_verification: number;
  verified_by_scan: number;
  closed_without_verification: number;
  active_risk_acceptances: number;
  expiring_acceptances: number;
  verification_rate: number | null;
}

const STATUS_STYLES: Record<string, string> = {
  open: "border-border bg-surface text-muted",
  assigned: "border-blue-500/40 bg-blue-500/10 text-blue-400",
  in_progress: "border-primary/40 bg-primary/10 text-primary",
  awaiting_verification: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400",
  verified: "border-green-500/40 bg-green-500/10 text-green-400",
  closed: "border-border bg-surface-hover text-muted",
  cancelled: "border-border bg-surface text-muted",
};

const SEVERITY_STYLES: Record<string, string> = {
  critical: "text-critical",
  high: "text-orange-500",
  medium: "text-yellow-500",
  low: "text-blue-400",
  info: "text-muted",
};

type Tab = "tasks" | "acceptances";

export default function RemediationPage() {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("tasks");
  const [showAll, setShowAll] = useState(false);
  const [fixing, setFixing] = useState<Task | null>(null);
  const [closing, setClosing] = useState<Task | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data: metrics } = useQuery({
    queryKey: ["remediation-metrics"],
    queryFn: () => api.get<Metrics>("/remediation/metrics"),
  });

  const { data: tasks = [], isLoading } = useQuery({
    queryKey: ["remediation-tasks", showAll],
    queryFn: () => api.get<Task[]>(`/remediation/tasks?open_only=${!showAll}`),
    enabled: tab === "tasks",
  });

  const { data: acceptances = [] } = useQuery({
    queryKey: ["risk-acceptances"],
    queryFn: () => api.get<Acceptance[]>("/remediation/risk-acceptances"),
    enabled: tab === "acceptances",
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["remediation-tasks"] });
    queryClient.invalidateQueries({ queryKey: ["remediation-metrics"] });
    queryClient.invalidateQueries({ queryKey: ["risk-acceptances"] });
  };

  const markFixed = useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) =>
      api.post(`/remediation/tasks/${id}/mark-fixed`, { note }),
    onSuccess: () => { invalidate(); setFixing(null); setError(null); },
    onError: (err: Error) => setError(err.message),
  });

  const closeTask = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post(`/remediation/tasks/${id}/close`, { reason }),
    onSuccess: () => { invalidate(); setClosing(null); setError(null); },
    onError: (err: Error) => setError(err.message),
  });

  const revoke = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post(`/remediation/risk-acceptances/${id}/revoke`, { reason }),
    onSuccess: invalidate,
  });

  return (
    <>
      <Topbar title="Remediation" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <div>
          <h1 className="text-2xl font-bold text-ink">Remediation</h1>
          <p className="text-sm text-muted">
            Work tracked from open to verified. A task is only marked verified when a scan
            stops seeing the finding.
          </p>
        </div>

        {/* Metrics */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <Metric label="Open tasks" value={metrics?.open_tasks} icon={<FileWarning className="h-4 w-4" />} />
          <Metric label="Overdue" value={metrics?.overdue_tasks} icon={<AlertTriangle className="h-4 w-4" />} tone="critical" />
          <Metric
            label="Awaiting verification"
            value={metrics?.awaiting_verification}
            icon={<Hourglass className="h-4 w-4" />}
            tone="warn"
            hint="An engineer has marked the work done. The task stays here until a scan confirms it."
          />
          <Metric label="Verified by scan" value={metrics?.verified_by_scan} icon={<ShieldCheck className="h-4 w-4" />} tone="ok" />
          <Metric
            label="Verification rate"
            value={metrics?.verification_rate != null ? `${metrics.verification_rate}%` : "—"}
            icon={<CheckCircle2 className="h-4 w-4" />}
            hint="Share of completed work a scan confirmed, rather than closed on assertion."
          />
        </div>

        {metrics != null && metrics.closed_without_verification > 0 &&
          metrics.verification_rate != null && metrics.verification_rate < 50 && (
          <div className="flex gap-3 rounded-xl border border-yellow-500/30 bg-yellow-500/5 p-4">
            <Info className="mt-0.5 h-5 w-5 shrink-0 text-yellow-500" />
            <p className="text-sm leading-relaxed text-muted">
              <span className="font-medium text-ink">
                Most completed work here was closed without a scan confirming it.
              </span>{" "}
              Closing without verification is sometimes correct — a decommissioned asset cannot
              be rescanned — but a programme where it is the norm is not measuring its own
              remediation.
            </p>
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border">
          {([["tasks", "Tasks"], ["acceptances", "Risk acceptances"]] as [Tab, string][]).map(
            ([value, label]) => (
              <button
                key={value}
                onClick={() => setTab(value)}
                className={cn(
                  "border-b-2 px-4 py-2.5 text-sm font-medium transition-colors",
                  tab === value
                    ? "border-primary text-primary"
                    : "border-transparent text-muted hover:text-ink"
                )}
              >
                {label}
              </button>
            )
          )}
        </div>

        {tab === "tasks" ? (
          <>
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted">
              <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
              Include closed and verified tasks
            </label>

            {isLoading ? (
              <p className="py-8 text-center text-sm text-muted">Loading…</p>
            ) : tasks.length === 0 ? (
              <div className="rounded-xl border border-dashed border-border p-12 text-center">
                <ShieldCheck className="mx-auto h-10 w-10 text-muted/40" />
                <p className="mt-3 text-sm text-ink/80">No remediation tasks</p>
                <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-muted">
                  Open a task from a finding to track the work, its owner and its due date.
                  This reflects the tasks created so far — not an assessment of your estate.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {tasks.map((task) => (
                  <div
                    key={task.id}
                    className={cn(
                      "rounded-xl border bg-surface p-4",
                      task.is_overdue ? "border-critical/40" : "border-border"
                    )}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={cn(
                            "rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                            STATUS_STYLES[task.status] ?? STATUS_STYLES.open
                          )}>
                            {task.status.replace(/_/g, " ")}
                          </span>
                          {task.finding_severity && (
                            <span className={cn(
                              "text-[10px] font-bold uppercase tracking-wider",
                              SEVERITY_STYLES[task.finding_severity]
                            )}>
                              {task.finding_severity}
                            </span>
                          )}
                          {task.finding_cve_id && (
                            <span className="font-mono text-[10px] text-muted">{task.finding_cve_id}</span>
                          )}
                          {task.is_overdue && (
                            <span className="inline-flex items-center gap-1 rounded border border-critical/40 bg-critical/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-critical">
                              <Clock className="h-2.5 w-2.5" /> overdue
                            </span>
                          )}
                        </div>

                        <p className="mt-1.5 text-sm font-medium text-ink">{task.title}</p>
                        <p className="mt-0.5 text-xs text-muted">
                          {task.asset_hostname && `${task.asset_hostname} · `}
                          {task.assigned_to_name ? `assigned to ${task.assigned_to_name}` : "unassigned"}
                          {task.due_date && ` · due ${task.due_date}`}
                          {task.sla_days != null && ` (${task.sla_days}-day SLA)`}
                        </p>

                        {task.status === "awaiting_verification" && (
                          <p className="mt-2 rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-2 text-[11px] leading-relaxed text-yellow-400/90">
                            Marked fixed{task.fixed_at && ` ${formatDistanceToNow(new Date(task.fixed_at), { addSuffix: true })}`}.
                            This stays open until a scan of the same asset no longer sees the finding.
                          </p>
                        )}

                        {task.status === "verified" && task.verified_by_scan_job_id && (
                          <p className="mt-2 rounded-lg border border-green-500/30 bg-green-500/5 p-2 text-[11px] leading-relaxed text-green-400/90">
                            Verified by a scan{task.verified_at && ` ${formatDistanceToNow(new Date(task.verified_at), { addSuffix: true })}`} —
                            the finding was no longer observed.
                          </p>
                        )}

                        {task.status === "closed" && (
                          <p className="mt-2 rounded-lg border border-border bg-surface-hover/40 p-2 text-[11px] leading-relaxed text-muted">
                            Closed without scan verification. {task.notes.split("\n").slice(-1)[0]}
                          </p>
                        )}
                      </div>

                      {!["verified", "closed", "cancelled"].includes(task.status) && (
                        <div className="flex shrink-0 gap-2">
                          {task.status !== "awaiting_verification" && (
                            <Button size="sm" variant="outline" onClick={() => { setError(null); setFixing(task); }}>
                              Mark fixed
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => { setError(null); setClosing(task); }}
                            className="border-border text-muted"
                          >
                            Close
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <>
            {acceptances.length === 0 ? (
              <div className="rounded-xl border border-dashed border-border p-12 text-center">
                <p className="text-sm text-ink/80">No risk acceptances recorded</p>
                <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-muted">
                  An acceptance records a decision to live with a finding until a stated date,
                  with a reason and a named approver. It expires automatically, and the finding
                  reopens.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {acceptances.map((acceptance) => {
                  const expiringSoon =
                    acceptance.status === "active" &&
                    acceptance.days_until_expiry != null &&
                    acceptance.days_until_expiry <= 30;

                  return (
                    <div
                      key={acceptance.id}
                      className={cn(
                        "rounded-xl border bg-surface p-4",
                        expiringSoon ? "border-yellow-500/40" : "border-border"
                      )}
                    >
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={cn(
                              "rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider",
                              acceptance.status === "active"
                                ? "border-blue-500/40 bg-blue-500/10 text-blue-400"
                                : acceptance.status === "expired"
                                  ? "border-orange-500/40 bg-orange-500/10 text-orange-400"
                                  : "border-border bg-surface text-muted"
                            )}>
                              {acceptance.status}
                            </span>
                            {expiringSoon && (
                              <span className="text-[10px] font-semibold text-yellow-400">
                                expires in {acceptance.days_until_expiry} day
                                {acceptance.days_until_expiry === 1 ? "" : "s"}
                              </span>
                            )}
                          </div>

                          <p className="mt-1.5 text-sm font-medium text-ink">
                            {acceptance.finding_title ?? "Finding"}
                          </p>
                          <p className="mt-1 text-sm leading-relaxed text-muted">{acceptance.reason}</p>
                          {acceptance.compensating_controls && (
                            <p className="mt-1 text-xs leading-relaxed text-muted/80">
                              Compensating controls: {acceptance.compensating_controls}
                            </p>
                          )}
                          <p className="mt-2 text-[10px] text-muted">
                            Expires {acceptance.expires_at}
                            {acceptance.approved_by_name && ` · approved by ${acceptance.approved_by_name}`}
                          </p>
                          {acceptance.revocation_reason && (
                            <p className="mt-1 text-[10px] text-muted">
                              Revoked: {acceptance.revocation_reason}
                            </p>
                          )}
                        </div>

                        {acceptance.status === "active" && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              const reason = window.prompt("Why is this acceptance being revoked?");
                              if (reason) revoke.mutate({ id: acceptance.id, reason });
                            }}
                            className="shrink-0 border-critical/50 text-critical hover:bg-critical/10"
                          >
                            <XCircle className="mr-1.5 h-3.5 w-3.5" /> Revoke
                          </Button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </main>

      <Modal open={fixing !== null} onClose={() => setFixing(null)} title="Mark as fixed">
        <NoteForm
          intro={
            <>
              <p className="text-sm leading-relaxed text-muted">
                This records that you believe the work is done. It does <strong className="text-ink">not</strong> close
                the finding — the task moves to <em>awaiting verification</em> and stays there until a scan
                of this asset no longer sees the finding.
              </p>
              <p className="mt-2 text-xs leading-relaxed text-muted/80">
                Run a scan against the asset to complete verification.
              </p>
            </>
          }
          label="What did you change? (optional)"
          required={false}
          error={error}
          pending={markFixed.isPending}
          submitLabel="Mark fixed"
          onSubmit={(note) => fixing && markFixed.mutate({ id: fixing.id, note })}
        />
      </Modal>

      <Modal open={closing !== null} onClose={() => setClosing(null)} title="Close without verification">
        <NoteForm
          intro={
            <p className="text-sm leading-relaxed text-muted">
              Use this when a scan cannot verify the fix — the asset was decommissioned, or the
              service was removed entirely. The task is recorded as <em>closed</em>, not{" "}
              <em>verified</em>, and the two are counted separately.
            </p>
          }
          label="Reason"
          required
          error={error}
          pending={closeTask.isPending}
          submitLabel="Close task"
          onSubmit={(reason) => closing && closeTask.mutate({ id: closing.id, reason })}
        />
      </Modal>
    </>
  );
}

function Metric({
  label, value, icon, tone = "neutral", hint,
}: {
  label: string;
  value: number | string | undefined;
  icon: React.ReactNode;
  tone?: "critical" | "warn" | "ok" | "neutral";
  hint?: string;
}) {
  const toneClass = {
    critical: "text-critical",
    warn: "text-yellow-500",
    ok: "text-green-500",
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

function NoteForm({
  intro, label, required, error, pending, submitLabel, onSubmit,
}: {
  intro: React.ReactNode;
  label: string;
  required: boolean;
  error: string | null;
  pending: boolean;
  submitLabel: string;
  onSubmit: (value: string) => void;
}) {
  const [value, setValue] = useState("");

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(value);
      }}
    >
      {intro}
      <div>
        <label className="mb-1 block text-xs font-medium text-muted">{label}</label>
        <textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          required={required}
          rows={3}
          className="w-full rounded-md border border-border bg-surface-hover px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
        />
      </div>
      {error && <p className="text-sm text-critical">{error}</p>}
      <Button type="submit" disabled={pending || (required && !value.trim())} className="w-full">
        {pending ? "Saving…" : submitLabel}
      </Button>
    </form>
  );
}
