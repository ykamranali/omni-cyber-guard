"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Topbar } from "@/components/layout/topbar";
import { Plus, Shield, AlertTriangle, ArrowRight, ArrowLeft } from "lucide-react";
import { api } from "@/lib/api";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { IncidentDrawer } from "@/components/incidents/incident-drawer";

interface Incident {
  id: string;
  title: string;
  description: string;
  status: "open" | "investigating" | "contained" | "resolved";
  severity: "critical" | "high" | "medium" | "low" | "info";
  created_at: string;
  resolved_at: string | null;
}

const COLUMNS = [
  { id: "open", title: "Open / Triage", color: "border-red-500/50 bg-red-500/5" },
  { id: "investigating", title: "Investigating", color: "border-orange-500/50 bg-orange-500/5" },
  { id: "resolved", title: "Resolved", color: "border-green-500/50 bg-green-500/5" }
] as const;

export default function IncidentsPage() {
  const queryClient = useQueryClient();
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);

  const { data: incidents, isLoading } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => api.get<Incident[]>("/incidents"),
  });

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string, status: Incident["status"] }) => 
      api.patch(`/incidents/${id}`, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    }
  });

  return (
    <>
      <Topbar title="Incident Response Playbook" />
      <main className="flex-1 flex flex-col overflow-hidden p-6 bg-background">
        <div className="flex flex-wrap justify-between items-center gap-4 mb-6 shrink-0">
          <div>
            <h1 className="text-2xl font-bold text-ink neon-text">Active Triage Board</h1>
            <p className="text-sm text-muted uppercase tracking-wider font-bold">Manage security incidents and coordinate response playbooks.</p>
          </div>
          <Button className="shadow-neon"><Plus size={16} className="mr-2" /> Report Incident</Button>
        </div>

        <div className="flex-1 flex gap-6 overflow-x-auto pb-4">
          {COLUMNS.map((col) => {
            const colIncidents = incidents?.filter(i => {
              if (col.id === "resolved") return i.status === "resolved" || i.status === "contained";
              return i.status === col.id;
            }) || [];

            return (
              <div key={col.id} className={cn("flex flex-col w-96 shrink-0 rounded-2xl border-t-4 bg-surface/40 backdrop-blur-md shadow-glass", col.color)}>
                <div className="p-4 border-b border-border/50 flex justify-between items-center bg-surface/50 rounded-t-2xl">
                  <h2 className="font-bold tracking-widest uppercase text-sm">{col.title}</h2>
                  <span className="bg-surface border border-border px-2 py-0.5 rounded-full text-xs font-mono">{colIncidents.length}</span>
                </div>
                
                <div className="flex-1 p-4 overflow-y-auto space-y-4">
                  {isLoading && <div className="text-center text-muted text-sm p-4">Loading...</div>}
                  {colIncidents.length === 0 && !isLoading && (
                    <div className="text-center text-muted text-xs p-8 opacity-50 border border-dashed border-border rounded-xl">No active incidents here.</div>
                  )}
                  {colIncidents.map(incident => (
                    <div 
                      key={incident.id} 
                      onClick={() => setSelectedIncident(incident)}
                      className="hud-panel p-4 flex flex-col gap-3 group relative hover:border-primary/50 transition-colors cursor-pointer"
                    >
                      <div className="flex justify-between items-start">
                        <div className="flex items-center gap-2">
                          {incident.severity === "critical" ? <AlertTriangle size={16} className="text-red-500 animate-pulse" /> : 
                           incident.severity === "high" ? <AlertTriangle size={16} className="text-orange-500" /> : 
                           <Shield size={16} className="text-blue-500" />}
                          <span className={cn(
                            "text-[10px] uppercase font-bold tracking-wider px-1.5 rounded",
                            incident.severity === "critical" ? "bg-red-500/20 text-red-500" :
                            incident.severity === "high" ? "bg-orange-500/20 text-orange-500" :
                            "bg-blue-500/20 text-blue-500"
                          )}>{incident.severity}</span>
                        </div>
                        <span className="text-[10px] text-muted font-mono">{formatDistanceToNow(new Date(incident.created_at))} ago</span>
                      </div>
                      
                      <div>
                        <h3 className="text-sm font-semibold text-ink line-clamp-2 leading-tight mb-1">{incident.title}</h3>
                        <p className="text-xs text-muted line-clamp-2 leading-relaxed">{incident.description || "No playbook details provided."}</p>
                      </div>

                      <div className="flex items-center justify-between mt-2 pt-3 border-t border-border/50">
                        <span className="text-[9px] text-muted font-mono truncate max-w-[120px]">ID: {incident.id.split('-')[0]}</span>
                        <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          {col.id !== "open" && (
                            <button 
                              onClick={(e) => { e.stopPropagation(); updateStatus.mutate({ id: incident.id, status: col.id === "resolved" ? "investigating" : "open" }); }}
                              className="p-1 hover:bg-surface-hover rounded text-muted hover:text-ink"
                              title="Move Back"
                            ><ArrowLeft size={14} /></button>
                          )}
                          {col.id !== "resolved" && (
                            <button 
                              onClick={(e) => { e.stopPropagation(); updateStatus.mutate({ id: incident.id, status: col.id === "open" ? "investigating" : "resolved" }); }}
                              className="p-1 hover:bg-surface-hover rounded text-muted hover:text-primary"
                              title="Advance Status"
                            ><ArrowRight size={14} /></button>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </main>

      {selectedIncident && (
        <IncidentDrawer 
          incident={incidents?.find((i) => i.id === selectedIncident.id) || selectedIncident} 
          onClose={() => setSelectedIncident(null)} 
        />
      )}
    </>
  );
}
