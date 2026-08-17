"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Topbar } from "@/components/layout/topbar";
import { FileWarning, Plus, Search, Shield, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

interface Incident {
  id: string;
  title: string;
  description: string;
  status: "open" | "investigating" | "contained" | "resolved";
  severity: "critical" | "high" | "medium" | "low" | "info";
  created_at: string;
  resolved_at: string | null;
}

export default function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState("all");

  const { data: incidents, isLoading } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => api.get<Incident[]>("/incidents"),
  });

  const filteredIncidents = incidents?.filter(i => statusFilter === "all" || i.status === statusFilter) || [];

  return (
    <>
      <Topbar title="Incident Response" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <div className="flex flex-wrap justify-between items-center gap-4">
          <div>
            <h1 className="text-2xl font-bold text-ink">Incident Management</h1>
            <p className="text-sm text-muted">Track and manage active security incidents and response lifecycles.</p>
          </div>
          <Button><Plus size={16} className="mr-2" /> Report Incident</Button>
        </div>

        <div className="flex gap-2 border-b border-border pb-4">
          {["all", "open", "investigating", "contained", "resolved"].map(status => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={cn(
                "px-4 py-2 rounded-full text-sm font-medium capitalize",
                statusFilter === status ? "bg-primary text-white" : "bg-surface text-muted hover:bg-surface-hover hover:text-ink border border-border"
              )}
            >
              {status}
            </button>
          ))}
        </div>

        <div className="grid gap-4">
          {isLoading ? (
            <div className="p-8 text-center text-muted">Loading incidents...</div>
          ) : filteredIncidents.length === 0 ? (
            <div className="rounded-xl border border-border bg-surface p-12 text-center text-muted">
              <FileWarning className="mx-auto h-12 w-12 opacity-20 mb-4" />
              <p>No incidents match the current filters.</p>
            </div>
          ) : (
            filteredIncidents.map(incident => (
              <div key={incident.id} className="flex gap-4 p-5 rounded-xl border border-border bg-surface hover:bg-surface-hover/50 transition-colors">
                <div className="mt-1 flex-shrink-0">
                  {incident.severity === "critical" ? (
                    <AlertTriangle className="h-6 w-6 text-red-500" />
                  ) : incident.severity === "high" ? (
                    <AlertTriangle className="h-6 w-6 text-orange-500" />
                  ) : (
                    <Shield className="h-6 w-6 text-blue-500" />
                  )}
                </div>
                <div className="flex-1 space-y-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-semibold text-ink">{incident.title}</h3>
                      <div className="mt-1 flex items-center gap-3 text-xs text-muted">
                        <span className="font-mono text-primary truncate max-w-[150px]">{incident.id}</span>
                        <span>•</span>
                        <span>Opened {formatDistanceToNow(new Date(incident.created_at), { addSuffix: true })}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                       <span className={cn(
                        "inline-flex rounded-full px-2 py-0.5 text-xs font-semibold uppercase",
                        incident.status === "resolved" ? "bg-green-500/10 text-green-500" :
                        incident.status === "open" ? "bg-red-500/10 text-red-500" : "bg-blue-500/10 text-blue-500"
                      )}>
                        {incident.status}
                      </span>
                      <span className={cn(
                        "inline-flex rounded-full px-2 py-0.5 text-xs font-semibold uppercase",
                        incident.severity === "critical" ? "bg-red-500/10 text-red-500" :
                        incident.severity === "high" ? "bg-orange-500/10 text-orange-500" :
                        "bg-yellow-500/10 text-yellow-500"
                      )}>
                        {incident.severity}
                      </span>
                    </div>
                  </div>
                  <p className="text-sm text-ink/80">{incident.description || "No description provided."}</p>
                </div>
              </div>
            ))
          )}
        </div>
      </main>
    </>
  );
}
