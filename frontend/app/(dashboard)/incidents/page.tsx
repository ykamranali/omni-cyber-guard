"use client";

import { useEffect, useState } from "react";
import { 
  ShieldAlert, AlertTriangle, ShieldCheck, 
  Search, Filter, ArrowRight, BrainCircuit, Activity
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api";
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

  useEffect(() => {
    fetchIncidents();
  }, []);

  const fetchIncidents = async () => {
    try {
      const res = await api.get<Incident[]>("/incidents");
      setIncidents(res);
    } catch (error) {
      console.error("Failed to load incidents:", error);
    } finally {
      setLoading(false);
    }
  };

  const generatePlaybook = async (id: string) => {
    try {
      setGeneratingFor(id);
      await api.post(`/incidents/${id}/playbook`);
      await fetchIncidents();
    } catch (error) {
      console.error("Failed to generate playbook:", error);
    } finally {
      setGeneratingFor(null);
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
        <button className="flex items-center gap-2 rounded-lg bg-rose-500 px-4 py-2 text-sm font-semibold text-white shadow-[0_0_15px_rgba(244,63,94,0.4)] transition-all hover:bg-rose-600">
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
            <button className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm font-medium text-ink transition-colors hover:bg-surface-hover">
              <Filter className="h-4 w-4" /> Filter
            </button>
          </div>
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
                    <button className="flex items-center justify-center rounded-lg border border-border p-2 text-muted transition-colors hover:bg-surface-hover hover:text-primary">
                      <ArrowRight className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
