"use client";

import { useEffect, useState } from "react";
import { 
  Wrench, CheckCircle2, Clock, AlertTriangle, 
  XCircle, Filter, Search, ArrowRight, Server, Play
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface User {
  id: string;
  email: string;
  full_name: string;
}

interface RemediationTask {
  id: string;
  title: string;
  status: "OPEN" | "IN_PROGRESS" | "AWAITING_VERIFICATION" | "VERIFIED" | "CLOSED" | "OVERDUE";
  priority: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  due_at: string | null;
  created_at: string;
  assigned_to?: User | null;
  finding_titles: string[];
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

  useEffect(() => {
    async function fetchTasks() {
      try {
        const res = await api.get<TasksResponse>("/remediation/tasks?size=50");
        setData(res);
      } catch (error) {
        console.error("Failed to load remediation tasks:", error);
      } finally {
        setLoading(false);
      }
    }
    fetchTasks();
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "OPEN": return <AlertTriangle className="h-4 w-4 text-amber-500" />;
      case "IN_PROGRESS": return <Play className="h-4 w-4 text-blue-500" />;
      case "AWAITING_VERIFICATION": return <Clock className="h-4 w-4 text-purple-500" />;
      case "VERIFIED": return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
      case "CLOSED": return <XCircle className="h-4 w-4 text-slate-500" />;
      case "OVERDUE": return <AlertTriangle className="h-4 w-4 text-rose-500" />;
      default: return null;
    }
  };

  const getStatusBadge = (status: string) => {
    const colors: Record<string, string> = {
      OPEN: "bg-amber-500/10 text-amber-500 border-amber-500/20",
      IN_PROGRESS: "bg-blue-500/10 text-blue-500 border-blue-500/20",
      AWAITING_VERIFICATION: "bg-purple-500/10 text-purple-500 border-purple-500/20",
      VERIFIED: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
      CLOSED: "bg-slate-500/10 text-slate-500 border-slate-500/20",
      OVERDUE: "bg-rose-500/10 text-rose-500 border-rose-500/20",
    };
    return (
      <span className={cn("flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold", colors[status])}>
        {getStatusIcon(status)}
        {status.replace("_", " ")}
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
        <button className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground shadow-[0_0_15px_rgba(var(--color-primary)/0.4)] transition-all hover:bg-primary/90">
          Create Task
        </button>
      </div>

      <div className="grid gap-6 md:grid-cols-4">
        {[
          { label: "Open Tasks", count: data?.items.filter(i => i.status === "OPEN").length || 0, color: "text-amber-500", bg: "bg-amber-500/20" },
          { label: "In Progress", count: data?.items.filter(i => i.status === "IN_PROGRESS").length || 0, color: "text-blue-500", bg: "bg-blue-500/20" },
          { label: "Awaiting Verification", count: data?.items.filter(i => i.status === "AWAITING_VERIFICATION").length || 0, color: "text-purple-500", bg: "bg-purple-500/20" },
          { label: "Overdue", count: data?.items.filter(i => i.status === "OVERDUE").length || 0, color: "text-rose-500", bg: "bg-rose-500/20" },
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
            <button className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm font-medium text-ink transition-colors hover:bg-surface-hover">
              <Filter className="h-4 w-4" /> Filter
            </button>
          </div>
          <div className="text-sm text-muted">
            {data?.items.length === 0 ? "No tasks found" : `Showing ${data?.items.length} tasks`}
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
                        task.priority === "CRITICAL" ? "border-rose-500 text-rose-500" :
                        task.priority === "HIGH" ? "border-amber-500 text-amber-500" :
                        task.priority === "MEDIUM" ? "border-blue-500 text-blue-500" :
                        "border-slate-500 text-slate-500"
                      )}>
                        {task.priority}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-muted">
                      {task.assigned_to ? (
                        <div className="flex items-center gap-1.5">
                          <div className="flex h-5 w-5 items-center justify-center rounded-full bg-primary/20 text-[10px] font-bold text-primary">
                            {task.assigned_to.full_name.charAt(0)}
                          </div>
                          <span>{task.assigned_to.full_name}</span>
                        </div>
                      ) : (
                        <span className="italic">Unassigned</span>
                      )}
                      
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3.5 w-3.5" />
                        <span>Created {formatDistanceToNow(new Date(task.created_at), { addSuffix: true })}</span>
                      </div>
                      
                      {task.due_at && (
                        <div className="flex items-center gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          <span className={new Date(task.due_at) < new Date() ? "text-rose-500 font-medium" : ""}>
                            Due {new Date(task.due_at).toLocaleDateString()}
                          </span>
                        </div>
                      )}
                    </div>

                    {task.finding_titles && task.finding_titles.length > 0 && (
                      <div className="mt-3 rounded-lg border border-border bg-surface px-3 py-2">
                        <p className="mb-1 text-xs font-medium uppercase tracking-wider text-muted">Target Findings</p>
                        <ul className="list-inside list-disc text-sm text-ink/80">
                          {task.finding_titles.slice(0, 3).map((ft, i) => (
                            <li key={i} className="truncate">{ft}</li>
                          ))}
                          {task.finding_titles.length > 3 && (
                            <li className="text-muted italic">+{task.finding_titles.length - 3} more</li>
                          )}
                        </ul>
                      </div>
                    )}
                  </div>

                  <button className="flex items-center justify-center rounded-lg border border-border p-2 text-muted transition-colors hover:bg-surface-hover hover:text-primary">
                    <ArrowRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
