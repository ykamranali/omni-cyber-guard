"use client";

import { useEffect, useState } from "react";
import { 
  ShieldCheck, ShieldBan, Globe, Server, 
  Search, Filter, Lock, Unlock, AlertTriangle, Network
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface BlockedIp {
  id: string;
  ip_address: string;
  reason: string;
  status: "active" | "expired" | "revoked";
  created_at: string;
  expires_at: string | null;
}

export default function InfrastructurePage() {
  const [blockedIps, setBlockedIps] = useState<BlockedIp[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [actionId, setActionId] = useState<string | null>(null);

  useEffect(() => {
    fetchBlockedIps();
  }, []);

  const fetchBlockedIps = async () => {
    try {
      const res = await api.get<BlockedIp[]>("/infrastructure/blocked-ips");
      setBlockedIps(res);
    } catch (error) {
      console.error("Failed to load blocked IPs:", error);
    } finally {
      setLoading(false);
    }
  };

  const unblockIp = async (id: string) => {
    try {
      setActionId(id);
      await api.delete(`/infrastructure/blocked-ips/${id}`);
      await fetchBlockedIps();
    } catch (error) {
      console.error("Failed to unblock IP:", error);
    } finally {
      setActionId(null);
    }
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <ShieldBan className="h-8 w-8 animate-pulse text-primary" />
          <p className="text-sm text-muted">Loading Infrastructure Protection...</p>
        </div>
      </div>
    );
  }

  const activeBlocks = blockedIps.filter(ip => ip.status === "active").length;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-ink">Infrastructure Protection</h1>
          <p className="mt-2 text-muted">Active defenses, firewall integrations, and blocklists</p>
        </div>
        <div className="flex gap-3">
          <button className="flex items-center gap-2 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-medium text-ink transition-all hover:bg-surface-hover">
            <Server className="h-4 w-4 text-muted" /> Firewall Settings
          </button>
          <button className="flex items-center gap-2 rounded-lg bg-rose-500 px-4 py-2 text-sm font-semibold text-white shadow-[0_0_15px_rgba(244,63,94,0.4)] transition-all hover:bg-rose-600">
            <ShieldBan className="h-4 w-4" /> Block IP
          </button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-4">
        <div className="glossy-card relative overflow-hidden rounded-xl border border-rose-500/30 p-6 shadow-lg">
          <div className="absolute -right-6 -top-6 rounded-full bg-rose-500/10 p-10 blur-3xl" />
          <p className="text-sm font-medium text-muted">Active Network Blocks</p>
          <div className="mt-2 flex items-center justify-between">
            <h3 className="text-3xl font-bold text-rose-500">{activeBlocks}</h3>
            <div className="rounded-lg bg-rose-500/20 p-2">
              <Lock className="h-5 w-5 text-rose-500" />
            </div>
          </div>
        </div>

        <div className="glossy-card relative overflow-hidden rounded-xl border border-border p-6 shadow-lg">
          <p className="text-sm font-medium text-muted">Integrations Active</p>
          <div className="mt-2 flex items-center justify-between">
            <h3 className="text-3xl font-bold text-ink">2</h3>
            <div className="rounded-lg bg-surface-hover p-2">
              <Network className="h-5 w-5 text-primary" />
            </div>
          </div>
          <div className="mt-4 flex gap-2 text-xs text-muted">
            <span className="rounded bg-surface px-2 py-0.5 border border-border">Palo Alto</span>
            <span className="rounded bg-surface px-2 py-0.5 border border-border">AWS WAF</span>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-surface shadow-lg backdrop-blur-xl">
        <div className="flex items-center justify-between border-b border-border p-4">
          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <input
                type="text"
                placeholder="Search IP address..."
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

        {blockedIps.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <Globe className="mb-4 h-12 w-12 text-muted/30" />
            <p className="text-lg font-medium text-ink">No Blocked IPs</p>
            <p className="mt-1 text-sm text-muted">The infrastructure blocklist is currently empty.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface-hover/50 text-xs uppercase tracking-wider text-muted">
                <tr>
                  <th className="px-6 py-4 font-medium">IP Address</th>
                  <th className="px-6 py-4 font-medium">Status</th>
                  <th className="px-6 py-4 font-medium">Reason</th>
                  <th className="px-6 py-4 font-medium">Blocked At</th>
                  <th className="px-6 py-4 font-medium">Expires</th>
                  <th className="px-6 py-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {blockedIps.map((ip) => (
                  <tr key={ip.id} className="transition-colors hover:bg-surface-hover/50">
                    <td className="px-6 py-4 font-mono font-bold text-rose-500">
                      {ip.ip_address}
                    </td>
                    <td className="px-6 py-4">
                      {ip.status === "active" && <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rose-500"><Lock className="h-3 w-3" /> Active</span>}
                      {ip.status === "expired" && <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-500/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-slate-500"><Unlock className="h-3 w-3" /> Expired</span>}
                      {ip.status === "revoked" && <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-emerald-500"><Unlock className="h-3 w-3" /> Revoked</span>}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-500" />
                        <span>{ip.reason}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-muted">
                      {formatDistanceToNow(new Date(ip.created_at), { addSuffix: true })}
                    </td>
                    <td className="px-6 py-4 text-muted font-mono">
                      {ip.expires_at ? new Date(ip.expires_at).toLocaleString() : "Never"}
                    </td>
                    <td className="px-6 py-4 text-right">
                      {ip.status === "active" && (
                        <button 
                          onClick={() => unblockIp(ip.id)}
                          disabled={actionId === ip.id}
                          className="rounded-lg border border-border bg-surface-hover px-3 py-1.5 text-xs font-medium text-ink transition-colors hover:bg-surface disabled:opacity-50"
                        >
                          {actionId === ip.id ? "Unblocking..." : "Unblock"}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
