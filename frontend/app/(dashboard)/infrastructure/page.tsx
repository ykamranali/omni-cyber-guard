"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Topbar } from "@/components/layout/topbar";
import { Shield, Plus, XCircle, Download, Activity, AlertOctagon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";

interface BlockedIP {
  ip: string;
  reason: string;
  blocked_at: string;
}

export default function InfrastructurePage() {
  const queryClient = useQueryClient();
  const [newIp, setNewIp] = useState("");
  const [reason, setReason] = useState("");

  const { data: blockedIps = [] } = useQuery({
    queryKey: ["blockedIps"],
    queryFn: () => api.get<BlockedIP[]>("/infrastructure/blocked-ips")
  });

  const blockMutation = useMutation({
    mutationFn: (data: { ip: string, reason: string }) => api.post("/infrastructure/blocked-ips", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["blockedIps"] });
      setNewIp("");
      setReason("");
    }
  });

  const unblockMutation = useMutation({
    mutationFn: (ip: string) => api.delete(`/infrastructure/blocked-ips/${ip}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["blockedIps"] })
  });

  const handleBlock = () => {
    if (!newIp) return;
    blockMutation.mutate({ ip: newIp, reason: reason || "Manual Block" });
  };

  const handleUnblock = (ip: string) => {
    unblockMutation.mutate(ip);
  };

  return (
    <>
      <Topbar title="Infrastructure Protection" />
      <main className="flex-1 space-y-6 overflow-y-auto p-6">
        <div>
          <h1 className="text-2xl font-bold text-ink">Active Defense & Mitigation</h1>
          <p className="text-sm text-muted">Manage firewall rules and active threat mitigations (TCP RST injection).</p>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          <div className="rounded-xl border border-border bg-surface p-6 shadow-sm">
            <h3 className="font-semibold text-ink flex items-center gap-2 mb-4">
              <Shield className="text-primary h-5 w-5" /> Block New IP
            </h3>
            <div className="space-y-4">
              <div>
                <label className="text-xs text-muted block mb-1">IP Address</label>
                <input 
                  value={newIp} onChange={e => setNewIp(e.target.value)}
                  className="w-full rounded-md border border-border bg-surface-hover px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary" 
                  placeholder="e.g. 192.168.1.100" 
                />
              </div>
              <div>
                <label className="text-xs text-muted block mb-1">Reason</label>
                <input 
                  value={reason} onChange={e => setReason(e.target.value)}
                  className="w-full rounded-md border border-border bg-surface-hover px-3 py-2 text-sm text-ink focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary" 
                  placeholder="e.g. Repeated SSH Bruteforce" 
                />
              </div>
              <Button onClick={handleBlock} className="w-full"><Plus className="mr-2 h-4 w-4" /> Block & Mitigate</Button>
            </div>
          </div>

          <div className="rounded-xl border border-border bg-surface p-6 shadow-sm">
             <h3 className="font-semibold text-ink flex items-center gap-2 mb-4">
              <Download className="text-primary h-5 w-5" /> Export Mitigation Scripts
            </h3>
            <p className="text-sm text-muted mb-4">Download shell scripts to manually apply these blocks directly to your server firewalls.</p>
            <div className="space-y-2 flex-col flex">
              <Button variant="outline" className="justify-start"><Download className="mr-2 h-4 w-4" /> Iptables (Linux)</Button>
              <Button variant="outline" className="justify-start"><Download className="mr-2 h-4 w-4" /> Windows Firewall (PowerShell)</Button>
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-surface overflow-hidden">
          <div className="border-b border-border p-4 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-ink flex items-center gap-2">
              <AlertOctagon className="text-red-500 h-5 w-5" /> Actively Blocked IPs
            </h2>
            <div className="flex items-center gap-1.5 text-xs text-primary animate-pulse ml-2 border border-primary/20 bg-primary/10 px-2 py-0.5 rounded-full">
               <span className="h-1.5 w-1.5 rounded-full bg-primary" /> ACTIVE TCP RST ENABLED
            </div>
          </div>
          
          <div className="divide-y divide-border">
            {blockedIps.length === 0 ? (
              <div className="p-8 text-center text-muted">No IPs currently blocked.</div>
            ) : (
              blockedIps.map(b => (
                <div key={b.ip} className="flex justify-between items-center p-4 hover:bg-surface-hover/50">
                  <div>
                    <p className="font-semibold text-ink font-mono">{b.ip}</p>
                    <p className="text-sm text-muted">{b.reason} • Blocked {new Date(b.blocked_at).toLocaleString()}</p>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => handleUnblock(b.ip)} className="text-critical border-critical/50 hover:bg-critical/10">
                    <XCircle className="h-4 w-4 mr-2" /> Unblock
                  </Button>
                </div>
              ))
            )}
          </div>
        </div>
      </main>
    </>
  );
}
