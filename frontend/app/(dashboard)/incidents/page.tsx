"use client";

import { useCallback, useEffect, useState } from "react";
import {
  ShieldAlert, AlertTriangle, ShieldCheck,
  Search, ArrowRight, BrainCircuit, Activity
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";
import { Modal } from "@/components/ui/modal";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Incident {
  id: string;
  title: string;
  description: string | null;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "investigating" | "mitigated" | "resolved";
  created_at: string;
  resolved_at: string | null;
  ai_playbook: string | null;
  asset_id: string | null;
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [generatingFor, setGeneratingFor] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [declareOpen, setDeclareOpen] = useState(false);
  const [declaring, setDeclaring] = useState(false);
  const [declareError, setDeclareError] = useState<string | null>(null);
  const [draft, setDraft] = useState({
    title: "",
    description: "",
    severity: "high",
  });

  const fetchIncidents = useCallback(async () => {
    const params = new URLSearchParams();
    if (search.trim()) params.set("search", search.trim());
    if (statusFilter) params.set("status", statusFilter);
    const query = params.toString();

    try {
      setIncidents(await api.get<Incident[]>(`/incidents${query ? `?${query}` : ""}`));
      setError(null);
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : "Incidents could not be loaded.",
      );
    } finally {
      setLoading(false);
    }
  }, [search, statusFilter]);

  // Debounced, and the filters are actually sent. `search` was previously set
  // on every keystroke and read by nothing.
  useEffect(() => {
    const timer = setTimeout(() => void fetchIncidents(), 250);
    return () => clearTimeout(timer);
  }, [fetchIncidents]);

  const generatePlaybook = async (id: string) => {
    setGeneratingFor(id);
    setError(null);
    try {
      await api.post(`/incidents/${id}/playbook`);
      await fetchIncidents();
    } catch (caught) {
      // A failure used to be swallowed to the console — and, on the backend,
      // written into the incident's playbook field as the exception text.
      setError(
        caught instanceof ApiError
          ? caught.message
          : "The playbook could not be generated. The incident is unchanged.",
      );
    } finally {
      setGeneratingFor(null);
    }
  };

  const declareIncident = async (event: React.FormEvent) => {
    event.preventDefault();
    setDeclaring(true);
    setDeclareError(null);
    try {
      await api.post("/incidents", {
        title: draft.title.trim(),
        description: draft.description.trim(),
        severity: draft.severity,
      });
      setDeclareOpen(false);
      setDraft({ title: "", description: "", severity: "high" });
      await fetchIncidents();
    } catch (caught) {
      setDeclareError(
        caught instanceof ApiError
          ? caught.message
          : "The incident could not be declared.",
      );
    } finally {
      setDeclaring(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "open": return "border-rose-500 text-rose-500 bg-rose-500/10";
      case "investigating": return "border-amber-500 text-amber-500 bg-amber-500/10";
      case "mitigated": return "border-blue-500 text-blue-500 bg-blue-500/10";
      case "resolved": return "border-emerald-500 text-emerald-500 bg-emerald-500/10";
      default: return "border-slate-500 text-slate-500 bg-slate-500/10";
    }
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <ShieldAlert className="h-8 w-8 animate-pulse text-primary" />
          <p className="text-sm text-muted">Loading Security Incidents...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-ink">Incident Response</h1>
          <p className="mt-2 text-muted">Track and resolve security incidents with AI-assisted playbooks</p>
        </div>
        {/* Was a dead button. Declaring an incident creates a real record
            through POST /incidents, which needs a title and a severity. */}
        <button
          type="button"
          onClick={() => setDeclareOpen(true)}
          className="flex items-center gap-2 rounded-lg bg-rose-500 px-4 py-2 text-sm font-semibold text-white shadow-[0_0_15px_rgba(244,63,94,0.4)] transition-all hover:bg-rose-600"
        >
          <ShieldAlert className="h-4 w-4" />
          Declare Incident
        </button>
      </div>

      <div className="grid gap-6 md:grid-cols-4">
        {[
          { label: "Active Incidents", count: incidents.filter(i => ["open", "investigating"].includes(i.status)).length, icon: ShieldAlert, color: "text-rose-500", bg: "bg-rose-500/20" },
          { label: "Critical Severity", count: incidents.filter(i => i.severity === "critical").length, icon: AlertTriangle, color: "text-amber-500", bg: "bg-amber-500/20" },
          { label: "Mitigated", count: incidents.filter(i => i.status === "mitigated").length, icon: Activity, color: "text-blue-500", bg: "bg-blue-500/20" },
          { label: "Resolved (30d)", count: incidents.filter(i => i.status === "resolved").length, icon: ShieldCheck, color: "text-emerald-500", bg: "bg-emerald-500/20" },
        ].map((stat, i) => (
          <div key={i} className="glossy-card relative overflow-hidden rounded-xl border border-border p-6 shadow-lg">
            <p className="text-sm font-medium text-muted">{stat.label}</p>
            <div className="mt-2 flex items-center justify-between">
              <h3 className={cn("text-3xl font-bold", stat.color)}>{stat.count}</h3>
              <div className={cn("rounded-lg p-2", stat.bg)}>
                <stat.icon className={cn("h-5 w-5", stat.color)} />
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
                placeholder="Search incidents..."
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
              <option value="investigating">Investigating</option>
              <option value="contained">Contained</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>

          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>

        {incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <ShieldCheck className="mb-4 h-12 w-12 text-emerald-500/50" />
            <p className="text-lg font-medium text-ink">No Active Incidents</p>
            <p className="mt-1 text-sm text-muted">Your environment is currently clear of security incidents.</p>
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {incidents.map((incident) => (
              <div key={incident.id} className="p-5 transition-colors hover:bg-surface-hover/50">
                <div className="flex items-start justify-between">
                  <div className="space-y-3 flex-1">
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-semibold text-primary">{incident.title}</h3>
                      <span className={cn("rounded-full border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider", getStatusColor(incident.status))}>
                        {incident.status}
                      </span>
                      <span className={cn(
                        "rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                        incident.severity === "critical" ? "bg-rose-500/20 text-rose-500" :
                        incident.severity === "high" ? "bg-amber-500/20 text-amber-500" :
                        incident.severity === "medium" ? "bg-blue-500/20 text-blue-500" :
                        "bg-slate-500/20 text-slate-500"
                      )}>
                        {incident.severity}
                      </span>
                    </div>

                    <p className="text-sm text-muted max-w-4xl">{incident.description}</p>
                    
                    <div className="flex items-center gap-4 text-xs text-muted">
                      <span>Opened {formatDistanceToNow(new Date(incident.created_at), { addSuffix: true })}</span>
                      {incident.asset_id && (
                        <span>Target Asset ID: <span className="font-mono text-ink">{incident.asset_id.substring(0, 8)}</span></span>
                      )}
                    </div>

                    {incident.ai_playbook ? (
                      <div className="mt-4 rounded-lg border border-primary/20 bg-primary/5 p-4">
                        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-primary">
                          <BrainCircuit className="h-4 w-4" /> AI Playbook Active
                        </div>
                        <div className="prose prose-sm prose-invert max-w-none text-ink/80 whitespace-pre-line">
                          {incident.ai_playbook}
                        </div>
                      </div>
                    ) : (
                      <div className="mt-4">
                        <button 
                          onClick={() => generatePlaybook(incident.id)}
                          disabled={generatingFor === incident.id}
                          className="flex items-center gap-2 rounded-lg border border-primary/30 bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/20 disabled:opacity-50"
                        >
                          <BrainCircuit className={cn("h-3.5 w-3.5", generatingFor === incident.id && "animate-pulse")} />
                          {generatingFor === incident.id ? "Generating..." : "Generate AI Playbook"}
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="ml-6 flex-shrink-0">
                    {/* Had no handler. An incident's most useful next step is
                        the asset it concerns, so this goes there when one is
                        linked and says so plainly when none is. */}
                    {incident.asset_id ? (
                      <Link
                        href={`/assets?asset=${incident.asset_id}`}
                        title="Open the affected asset"
                        className="flex items-center justify-center rounded-lg border border-border p-2 text-muted transition-colors hover:bg-surface-hover hover:text-primary"
                      >
                        <ArrowRight className="h-4 w-4" />
                      </Link>
                    ) : (
                      <span className="block max-w-[7rem] text-right text-[11px] text-muted">
                        No asset linked
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <Modal
        open={declareOpen}
        onClose={() => setDeclareOpen(false)}
        title="Declare an incident"
      >
        <form className="space-y-4" onSubmit={declareIncident}>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Title</label>
            <input
              value={draft.title}
              onChange={(e) => setDraft({ ...draft, title: e.target.value })}
              required
              placeholder="Suspicious authentication activity on the VPN"
              className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-ink focus:border-primary focus:outline-none"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Severity</label>
            <select
              value={draft.severity}
              onChange={(e) => setDraft({ ...draft, severity: e.target.value })}
              className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm capitalize text-ink focus:border-primary focus:outline-none"
            >
              {["critical", "high", "medium", "low", "info"].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-muted">
              What was observed
            </label>
            <textarea
              value={draft.description}
              onChange={(e) => setDraft({ ...draft, description: e.target.value })}
              rows={4}
              placeholder="What happened, when, and what you have seen so far."
              className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none"
            />
            <p className="mt-1 text-[11px] text-muted">
              Record what was observed, not what you infer from it — the
              distinction matters when this is read back later.
            </p>
          </div>

          {declareError && (
            <p className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-400">
              {declareError}
            </p>
          )}

          <button
            type="submit"
            disabled={!draft.title.trim() || declaring}
            className="w-full rounded-lg bg-rose-500 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-50"
          >
            {declaring ? "Declaring…" : "Declare incident"}
          </button>
        </form>
      </Modal>
    </div>
  );
}
