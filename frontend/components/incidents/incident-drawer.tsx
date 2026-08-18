"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { X, Bot, Shield, AlertTriangle, FileText, Loader2 } from "lucide-react";
import ReactMarkdown from "react-markdown";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface IncidentDrawerProps {
  incident: any | null;
  onClose: () => void;
}

export function IncidentDrawer({ incident, onClose }: IncidentDrawerProps) {
  const [activeTab, setActiveTab] = useState<"overview" | "playbook">("overview");
  const queryClient = useQueryClient();

  const generatePlaybook = useMutation({
    mutationFn: () => api.post(`/incidents/${incident.id}/playbook`),
    onSuccess: (updatedIncident: any) => {
      // We mutate the local incident state or rely on React Query cache update
      queryClient.setQueryData(["incidents"], (old: any) => 
        old.map((i: any) => i.id === updatedIncident.id ? updatedIncident : i)
      );
      // Since `incident` prop might not update instantly, we could force a refresh or rely on parent
    }
  });

  if (!incident) return null;

  return (
    <>
      {/* Backdrop */}
      <div 
        className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm"
        onClick={onClose}
      />
      
      {/* Sliding Drawer */}
      <div className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl bg-surface border-l border-border/50 shadow-glass transform transition-transform duration-300 flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-border/50 bg-background/50">
          <div className="flex items-center gap-3">
            {incident.severity === "critical" ? <AlertTriangle size={24} className="text-red-500 animate-pulse" /> : 
             incident.severity === "high" ? <AlertTriangle size={24} className="text-orange-500" /> : 
             <Shield size={24} className="text-blue-500" />}
            <div>
              <h2 className="text-xl font-bold text-ink neon-text line-clamp-1">{incident.title}</h2>
              <div className="flex items-center gap-2 mt-1">
                <span className={cn(
                  "text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded",
                  incident.severity === "critical" ? "bg-red-500/20 text-red-500 border border-red-500/50" :
                  incident.severity === "high" ? "bg-orange-500/20 text-orange-500 border border-orange-500/50" :
                  "bg-blue-500/20 text-blue-500 border border-blue-500/50"
                )}>{incident.severity}</span>
                <span className="text-xs text-muted font-mono">{formatDistanceToNow(new Date(incident.created_at))} ago</span>
                <span className="text-xs text-muted font-mono border-l border-border/50 pl-2">ID: {incident.id.split("-")[0]}</span>
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-surface-hover rounded-full text-muted hover:text-ink transition-colors">
            <X size={20} />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-border/50 bg-background/30 px-6 gap-6">
          <button 
            className={cn("py-4 text-sm font-bold tracking-wider uppercase border-b-2 transition-colors", activeTab === "overview" ? "border-primary text-primary" : "border-transparent text-muted hover:text-ink")}
            onClick={() => setActiveTab("overview")}
          >
            <div className="flex items-center gap-2"><FileText size={16} /> Overview</div>
          </button>
          <button 
            className={cn("py-4 text-sm font-bold tracking-wider uppercase border-b-2 transition-colors", activeTab === "playbook" ? "border-primary text-primary" : "border-transparent text-muted hover:text-ink")}
            onClick={() => setActiveTab("playbook")}
          >
            <div className="flex items-center gap-2"><Bot size={16} className={incident.ai_playbook ? "text-primary" : ""} /> AI Playbook</div>
          </button>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-6 scrollbar-thin">
          {activeTab === "overview" && (
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-bold text-ink uppercase tracking-widest mb-3">Incident Description</h3>
                <div className="p-4 rounded-xl bg-surface-hover/30 border border-border/50 text-sm text-ink/80 leading-relaxed whitespace-pre-wrap">
                  {incident.description || "No description provided."}
                </div>
              </div>
              
              <div>
                <h3 className="text-sm font-bold text-ink uppercase tracking-widest mb-3">Status</h3>
                <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-surface-hover border border-border/50 text-xs font-mono font-bold uppercase text-ink/80">
                  <div className={cn("w-2 h-2 rounded-full", incident.status === "resolved" ? "bg-green-500" : incident.status === "investigating" ? "bg-orange-500" : "bg-red-500")} />
                  {incident.status}
                </div>
              </div>
            </div>
          )}

          {activeTab === "playbook" && (
            <div className="h-full flex flex-col">
              {incident.ai_playbook ? (
                <div className="prose prose-invert prose-sm max-w-none prose-pre:bg-black/50 prose-pre:border prose-pre:border-border/50 prose-a:text-primary hover:prose-a:text-primary-hover">
                  <ReactMarkdown>{incident.ai_playbook}</ReactMarkdown>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
                  <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mb-6 shadow-neon">
                    <Bot size={32} className="text-primary" />
                  </div>
                  <h3 className="text-lg font-bold text-ink mb-2">Automated Remediation Playbook</h3>
                  <p className="text-sm text-muted max-w-md mb-8 leading-relaxed">
                    Omni Cyber Guard can analyze this incident's context and generate a step-by-step remediation playbook, complete with containment strategies and necessary commands.
                  </p>
                  <button 
                    onClick={() => generatePlaybook.mutate()}
                    disabled={generatePlaybook.isPending}
                    className="flex items-center gap-2 px-6 py-3 rounded-full bg-primary text-primary-foreground font-bold hover:bg-primary-hover transition-all shadow-neon disabled:opacity-50"
                  >
                    {generatePlaybook.isPending ? <Loader2 size={18} className="animate-spin" /> : <Bot size={18} />}
                    {generatePlaybook.isPending ? "Generating Playbook..." : "Generate AI Playbook"}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
