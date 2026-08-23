"use client";

import { useEffect, useState } from "react";
import { 
  Wrench, CheckCircle2, Clock, AlertTriangle, 
  XCircle, Filter, Search, ArrowRight, Server, Play, Plus
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Matches what the API actually returns.
 *
 * The previous interface described a different shape entirely — `due_at`,
 * `assigned_to` as an object, a `finding_titles` array, and uppercase status
 * and priority values. The API returns `due_date`, `assigned_to_name`,
 * `finding_severity`/`finding_cve_id`, and lowercase enum values, so every
 * badge fell through to its default, every due date rendered blank, and the
 * assignee never appeared. That is why this page looked broken.
 */
interface RemediationTask {
  id: string;
  finding_id: string;
  asset_id: string | null;
  title: string;
  description: string;
  status:
    | "open" | "assigned" | "in_progress" | "fixed"
    | "awaiting_verification" | "verified" | "closed" | "cancelled";
  priority: "urgent" | "high" | "medium" | "low";
  due_date: string | null;
  created_at: string;
  is_overdue: boolean;
  days_until_due: number | null;
  verified_by_scan_job_id: string | null;
  finding_severity: string | null;
  finding_cve_id: string | null;
  asset_hostname: string | null;
  assigned_to_name: string | null;
}

interface TasksResponse {
  items: RemediationTask[];
  total: number;
  page: number;
  size: number;
}

export default function RemediationPage() {
  const [data, setData] = useState<TasksResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // The search box and the status control now actually run a query. `search`
  // was previously set on every keystroke and read by nothing, and the request
  // was a fixed "/remediation/tasks?size=50".
  useEffect(() => {
    const controller = setTimeout(async () => {
      setLoading(true);
      const params = new URLSearchParams({ limit: "100" });
      if (search.trim()) params.set("search", search.trim());
      if (statusFilter) params.set("status", statusFilter);
      if (showAll) params.set("open_only", "false");

      try {
        const rows = await api.get<RemediationTask[]>(
          `/remediation/tasks?${params.toString()}`,
        );
        setData({ items: rows, total: rows.length, page: 1, size: rows.length });
        setError(null);
      } catch (caught) {
        setError(
          caught instanceof ApiError
            ? caught.message
            : "Remediation tasks could not be loaded.",
        );
      } finally {
        setLoading(false);
      }
    }, 250);

    return () => clearTimeout(controller);
  }, [search, statusFilter, showAll]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "open":
      case "assigned": return <AlertTriangle className="h-4 w-4 text-amber-500" />;
      case "in_progress": return <Play className="h-4 w-4 text-blue-500" />;
      case "fixed":
      case "awaiting_verification": return <Clock className="h-4 w-4 text-purple-500" />;
      case "verified": return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
      case "CLOSED": return <XCircle className="h-4 w-4 text-slate-500" />;
      case "OVERDUE": return <AlertTriangle className="h-4 w-4 text-rose-500" />;
      default: return null;
    }
  };

  const getStatusBadge = (status: string) => {
    // Keys match the API's lowercase enum values. They were uppercase, so
    // every badge fell through to no colour at all.
    const colors: Record<string, string> = {
      open: "bg-amber-500/10 text-amber-500 border-amber-500/20",
      assigned: "bg-amber-500/10 text-amber-500 border-amber-500/20",
      in_progress: "bg-blue-500/10 text-blue-500 border-blue-500/20",
      fixed: "bg-purple-500/10 text-purple-500 border-purple-500/20",
      awaiting_verification: "bg-purple-500/10 text-purple-500 border-purple-500/20",
      verified: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
      closed: "bg-slate-500/10 text-slate-500 border-slate-500/20",
      cancelled: "bg-slate-500/10 text-slate-500 border-slate-500/20",
    };
    return (
      <span className={cn(
        "flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold capitalize",
        colors[status] ?? "bg-surface-hover text-muted border-border",
      )}>
        {getStatusIcon(status)}
        {status.replace(/_/g, " ")}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Wrench className="h-8 w-8 animate-spin text-primary" />
          <p className="text-sm text-muted">Loading Remediation Tasks...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-ink">Remediation</h1>
          <p className="mt-2 text-muted">Track and verify vulnerability fixes</p>
        </div>
        {/* A remediation task is opened against a specific finding — there is
            nothing to remediate without one — so this points at the finding
            list rather than offering a form with no subject. The button
            previously had no handler at all. */}
        <Link
          href="/vulnerabilities"
          className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground shadow-[0_0_15px_rgba(var(--color-primary)/0.4)] transition-all hover:bg-primary/90"
        >
          <Plus className="h-4 w-4" />
          Open a task from a finding
        </Link>
      </div>

      <div className="grid gap-6 md:grid-cols-4">
        {[
          { label: "Open", count: data?.items.filter(i => i.status === "open" || i.status === "assigned").length || 0, color: "text-amber-500", bg: "bg-amber-500/20" },
          { label: "In progress", count: data?.items.filter(i => i.status === "in_progress").length || 0, color: "text-blue-500", bg: "bg-blue-500/20" },
          // Reported fixed, not yet confirmed by a rescan. Deliberately its own
          // number: this is the gap between "someone said so" and "verified".
          { label: "Awaiting verification", count: data?.items.filter(i => i.status === "awaiting_verification" || i.status === "fixed").length || 0, color: "text-purple-500", bg: "bg-purple-500/20" },
          { label: "Overdue", count: data?.items.filter(i => i.is_overdue).length || 0, color: "text-rose-500", bg: "bg-rose-500/20" },
        ].map((stat, i) => (
          <div key={i} className="glossy-card relative overflow-hidden rounded-xl border border-border p-6 shadow-lg">
            <p className="text-sm font-medium text-muted">{stat.label}</p>
            <div className="mt-2 flex items-center justify-between">
              <h3 className={cn("text-3xl font-bold", stat.color)}>{stat.count}</h3>
              <div className={cn("rounded-lg p-2", stat.bg)}>
                <Wrench className={cn("h-5 w-5", stat.color)} />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-border bg-surface shadow-lg backdrop-blur-xl">
        <div className="flex items-center justify-between border-b border-border p-4">
          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <input
                type="text"
                placeholder="Search tasks..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="h-10 w-64 rounded-lg border border-border bg-surface-hover pl-9 pr-4 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="h-10 rounded-lg border border-border bg-surface-hover px-3 text-sm text-ink focus:border-primary focus:outline-none"
            >
              <option value="">Any status</option>
              <option value="open">Open</option>
              <option value="assigned">Assigned</option>
              <option value="in_progress">In progress</option>
              <option value="awaiting_verification">Awaiting verification</option>
              <option value="verified">Verified</option>
              <option value="closed">Closed</option>
            </select>

            <label className="flex items-center gap-2 text-xs text-muted">
              <input
                type="checkbox"
                checked={showAll}
                onChange={(e) => setShowAll(e.target.checked)}
              />
              Include completed
            </label>
          </div>
          <div className="text-sm text-muted">
            {loading
              ? "Loading…"
              : data?.items.length === 0
                ? "No tasks match"
                : `Showing ${data?.items.length} task(s)`}
          </div>
        </div>

        {data?.items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <CheckCircle2 className="mb-4 h-12 w-12 text-muted/30" />
            <p className="text-lg font-medium text-ink">No tasks found</p>
            <p className="mt-1 text-sm text-muted">Your remediation queue is currently empty.</p>
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {data?.items.map((task) => (
              <div key={task.id} className="p-4 transition-colors hover:bg-surface-hover/50">
                <div className="flex items-start justify-between">
                  <div className="space-y-3">
                    <div className="flex items-center gap-3">
                      <h3 className="font-semibold text-primary">{task.title}</h3>
                      {getStatusBadge(task.status)}
                      <span className={cn(
                        "rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border",
                        task.priority === "urgent" ? "border-rose-500 text-rose-500" :
                        task.priority === "high" ? "border-amber-500 text-amber-500" :
                        task.priority === "medium" ? "border-blue-500 text-blue-500" :
                        "border-slate-500 text-slate-500"
                      )}>
                        {task.priority}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-muted">
                      {task.assigned_to_name ? (
                        <div className="flex items-center gap-1.5">
                          <div className="flex h-5 w-5 items-center justify-center rounded-full bg-primary/20 text-[10px] font-bold text-primary">
                            {task.assigned_to_name.charAt(0)}
                          </div>
                          <span>{task.assigned_to_name}</span>
                        </div>
                      ) : (
                        <span className="italic">Unassigned</span>
                      )}
                      
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3.5 w-3.5" />
                        <span>Created {formatDistanceToNow(new Date(task.created_at), { addSuffix: true })}</span>
                      </div>
                      
                      {task.due_date && (
                        <div className="flex items-center gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          <span className={task.is_overdue ? "font-medium text-rose-500" : ""}>
                            Due {new Date(task.due_date).toLocaleDateString()}
                            {task.days_until_due !== null &&
                              ` (${task.days_until_due < 0
                                ? `${Math.abs(task.days_until_due)}d overdue`
                                : `${task.days_until_due}d left`})`}
                          </span>
                        </div>
                      )}

                      {task.asset_hostname && (
                        <div className="flex items-center gap-1.5">
                          <Server className="h-3.5 w-3.5" />
                          <span>{task.asset_hostname}</span>
                        </div>
                      )}
                    </div>

                    <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                      {task.finding_severity && (
                        <span className="rounded-md border border-border bg-surface px-2 py-0.5 capitalize text-ink/80">
                          {task.finding_severity} finding
                        </span>
                      )}
                      {task.finding_cve_id && (
                        <code className="rounded-md border border-border bg-surface px-2 py-0.5 text-ink/80">
                          {task.finding_cve_id}
                        </code>
                      )}
                      {/* The distinction the whole remediation model turns on:
                          only a rescan can move a task to verified, and its
                          absence is meaningful. */}
                      {task.status === "verified" ? (
                        <span className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-400">
                          Confirmed by a rescan
                        </span>
                      ) : task.status === "closed" ? (
                        <span className="rounded-md border border-border bg-surface px-2 py-0.5 text-muted">
                          Closed without scan confirmation
                        </span>
                      ) : null}
                    </div>
                  </div>

                  {/* Went nowhere. A remediation task is only meaningful next
                      to the finding it exists for, so this opens that. */}
                  <Link
                    href={`/vulnerabilities?finding=${task.finding_id}`}
                    title="Open the finding this task was raised for"
                    className="flex items-center justify-center rounded-lg border border-border p-2 text-muted transition-colors hover:bg-surface-hover hover:text-primary"
                  >
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
